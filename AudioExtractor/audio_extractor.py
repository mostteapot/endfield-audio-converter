from __future__ import annotations

import os
import queue
import shutil
import json
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import posixpath
import re
import tkinter as tk
import wave
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

MAGIC1 = 0x9C5A0B29
MAGIC2 = 0x04E11C23
MASK32 = 0xFFFFFFFF


def generate_hash(seed_value: int) -> int:
    """Hypergryph's 32-bit XOR/multiply word-key function."""
    value = seed_value & 0xFF
    value = ((value ^ MAGIC1) * MAGIC2) & MASK32
    value = (value ^ ((seed_value >> 8) & 0xFF)) * MAGIC2 & MASK32
    value = (value ^ ((seed_value >> 16) & 0xFF)) * MAGIC2 & MASK32
    value = (value ^ ((seed_value >> 24) & 0xFF)) * MAGIC2 & MASK32
    return value


def fnv_hash(text: str, variant: str = "fnv1", bits: int = 32, lowercase: bool = True) -> int:
    """Hash a candidate name using an FNV variant (Wwise commonly uses FNV-1 32-bit)."""
    if bits not in (32, 64):
        raise ValueError("FNV width must be 32 or 64 bits.")
    if variant not in ("fnv1", "fnv1a"):
        raise ValueError("FNV variant must be fnv1 or fnv1a.")
    if lowercase:
        text = text.lower()
    offset_basis, prime = ((0x811C9DC5, 0x01000193) if bits == 32 else (0xCBF29CE484222325, 0x100000001B3))
    mask = (1 << bits) - 1
    value = offset_basis
    for byte in text.encode("utf-8"):
        if variant == "fnv1a":
            value ^= byte
            value = value * prime & mask
        else:
            value = value * prime & mask
            value ^= byte
    return value


@lru_cache(maxsize=500_000)
def natural_sort_key(value: str) -> tuple[tuple[int, object], ...]:
    """Compare digit runs numerically so name_2 sorts before name_11."""
    return tuple(
        (1, int(part)) if part.isdigit() else (0, part.casefold())
        for part in re.split(r"(\d+)", str(value))
    )


def natural_sort_compare(left: str, right: str) -> int:
    left_key, right_key = natural_sort_key(left), natural_sort_key(right)
    return (left_key > right_key) - (left_key < right_key)


def decipher(data: bytes | bytearray, seed: int, offset_to_file_start: int = 0) -> bytes:
    """XOR-decrypt bytes with the game's position-dependent word key."""
    if len(data) >= 4 * 1024 and offset_to_file_start % 4 == 0:
        try:
            import numpy as np

            full_words = len(data) // 4
            counters = np.arange(full_words, dtype=np.uint32) + np.uint32((seed + (offset_to_file_start >> 2)) & MASK32)
            keys = ((counters & np.uint32(0xFF)) ^ np.uint32(MAGIC1)) * np.uint32(MAGIC2)
            keys = (keys ^ ((counters >> np.uint32(8)) & np.uint32(0xFF))) * np.uint32(MAGIC2)
            keys = (keys ^ ((counters >> np.uint32(16)) & np.uint32(0xFF))) * np.uint32(MAGIC2)
            keys = (keys ^ ((counters >> np.uint32(24)) & np.uint32(0xFF))) * np.uint32(MAGIC2)
            payload = np.frombuffer(data[:full_words * 4], dtype="<u4")
            result = (payload ^ keys).astype("<u4", copy=False).tobytes()
            tail = data[full_words * 4:]
            if tail:
                result += decipher(tail, seed, offset_to_file_start + full_words * 4)
            return result
        except ImportError:
            pass
    out = bytearray(data)
    position = 0
    counter = (seed + (offset_to_file_start >> 2)) & MASK32
    misalignment = offset_to_file_start & 3
    if misalignment:
        key = generate_hash(counter).to_bytes(4, "little")
        lead = min(4 - misalignment, len(out))
        for i in range(lead):
            out[position] ^= key[misalignment + i]
            position += 1
        counter = (counter + 1) & MASK32
    while position + 4 <= len(out):
        key = generate_hash(counter).to_bytes(4, "little")
        for i in range(4):
            out[position + i] ^= key[i]
        position += 4
        counter = (counter + 1) & MASK32
    if position < len(out):
        key = generate_hash(counter).to_bytes(4, "little")
        for i in range(len(out) - position):
            out[position + i] ^= key[i]
    return bytes(out)


def decrypt_pck_header(raw: bytes) -> tuple[bytes, int]:
    if len(raw) < 12:
        raise ValueError("File is too small to be a PCK package.")
    magic = raw[:4]
    if magic == b"AKPK":
        header_size = struct.unpack_from("<I", raw, 4)[0]
        header_end = 8 + header_size
        if header_end > len(raw):
            raise ValueError("PCK header size points past end of file.")
        return raw[:header_end], header_end
    if magic != b":)xD":
        raise ValueError(f"Unrecognized PCK magic: {magic!r}")
    header_size = struct.unpack_from("<I", raw, 4)[0]
    header_end = 8 + header_size
    if header_size < 4 or header_size > 512 * 1024 * 1024 or header_end > len(raw):
        raise ValueError("Invalid encrypted PCK header size.")
    header = bytearray(raw[:header_end])
    start = 12
    header[start:header_end] = decipher(header[start:header_end], header_size, 0)
    if header[:4] != b":)xD":
        raise ValueError("PCK header decryption produced an unexpected header.")
    return bytes(header), header_end


def parse_entries(header: bytes, file_size: int | None = None, header_end: int = 0) -> list[tuple[int, int, int]]:
    """Return (file_id, file_offset, file_size), supporting 32/64-bit IDs."""
    failures: list[str] = []
    # Some Endfield packages use 32-bit IDs (20-byte records), others use
    # 64-bit IDs (24-byte records). For 64-bit records, the count sits one word
    # before the record start; for 32-bit records it sits two words before the
    # record's flag. Try both count positions and validate all offsets.
    for flag_offset in range(0x24, len(header) - 4, 4):
        if header[flag_offset:flag_offset + 4] != b"\x01\x00\x00\x00":
            continue
        for count_offset in (flag_offset - 8, flag_offset - 12):
            if count_offset < 0:
                continue
            position = count_offset
            results: list[tuple[int, int, int]] = []
            valid = True
            for table_index in range(2):
                if position + 4 > len(header):
                    break
                count = struct.unpack_from("<I", header, position)[0]
                position += 4
                if count > 2_000_000 or (table_index == 0 and count == 0):
                    valid = False
                    break
                for _ in range(count):
                    if position + 20 > len(header):
                        valid = False
                        break
                    words = struct.unpack_from("<5I", header, position)
                    record = None
                    # Prefer a valid 64-bit layout. Some 64-bit IDs have a high
                    # word of 1, which superficially resembles the 32-bit flag.
                    if position + 24 <= len(header):
                        extra = struct.unpack_from("<I", header, position + 20)[0]
                        if words[2] == 1 and extra in (0, 1):
                            candidate = (words[0] | (words[1] << 32), words[4], words[3])
                            if candidate[2] > 0 and candidate[1] >= header_end and (
                                file_size is None or candidate[1] + candidate[2] <= file_size
                            ):
                                record = (candidate, 24)
                    if record is None and words[1] == 1 and words[4] in (0, 1):
                        candidate = (words[0], words[3], words[2])
                        if candidate[2] > 0 and candidate[1] >= header_end and (
                            file_size is None or candidate[1] + candidate[2] <= file_size
                        ):
                            record = (candidate, 20)
                    if record is None:
                        valid = False
                        break
                    results.append(record[0])
                    position += record[1]
                if not valid:
                    break
            if valid and results:
                return results
        failures.append(f"candidate at 0x{flag_offset:X} was inconsistent")
    detail = failures[0] if failures else "no candidate flag was found"
    raise ValueError(f"Could not parse Wwise PCK entries: {detail}.")


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(2, 100000):
        candidate = path.with_name(f"{path.stem}_{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError(f"Could not make a unique output name for {path.name}")


def extract_pck(pck_path: Path, output_dir: Path) -> tuple[int, list[Path]]:
    file_size = pck_path.stat().st_size
    with pck_path.open("rb") as package:
        prefix = package.read(8)
        if len(prefix) < 8:
            raise ValueError("File is too small to be a PCK package.")
        header_size = struct.unpack_from("<I", prefix, 4)[0]
        header_end = 8 + header_size
        if header_end > file_size or header_size > 512 * 1024 * 1024:
            raise ValueError("Invalid PCK header size.")
        package.seek(0)
        header_bytes = package.read(header_end)
        header, header_end = decrypt_pck_header(header_bytes)
    entries = parse_entries(header, file_size=file_size, header_end=header_end)
    written: list[Path] = []
    with pck_path.open("rb") as package:
        for file_id, offset, size in entries:
            if size <= 0 or offset < header_end or offset + size > file_size:
                continue
            package.seek(offset)
            encrypted = package.read(size)
            if len(encrypted) != size:
                continue
            decoded = encrypted if encrypted[:4] in (b"RIFF", b"BKHD", b"PLUG") else decipher(encrypted, file_id & MASK32, 0)
            if decoded.startswith(b"RIFF"):
                extension = ".wem"
            elif decoded.startswith(b"BKHD"):
                extension = ".bnk"
            elif decoded.startswith(b"PLUG"):
                extension = ".plug"
            else:
                continue
            destination = unique_path(output_dir / f"{pck_path.stem}_{file_id}{extension}")
            destination.write_bytes(decoded)
            written.append(destination)
    return len(entries), written


class AudioExtractorApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Endfield Audio Extractor")
        self.root.geometry("790x590")
        self.root.minsize(680, 480)
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.running = False
        self._closing = False
        self._poll_after_id: str | None = None

        self.input_var = tk.StringVar()
        self.output_var = tk.StringVar(value=str(Path.cwd() / "Audio output"))
        self.vgm_var = tk.StringVar(value=self._find_vgmstream())
        self.ffmpeg_var = tk.StringVar(value=self._find_ffmpeg())
        self.wav_var = tk.BooleanVar(value=bool(self.vgm_var.get()))
        self.mp3_var = tk.BooleanVar(value=False)
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll_after_id = self.root.after(100, self._poll_events)

    @staticmethod
    def _find_tool(*names: str) -> str:
        for name in names:
            found = shutil.which(name)
            if found:
                return found
        return ""

    @classmethod
    def _find_vgmstream(cls) -> str:
        preferred = Path.home() / "Downloads" / "vgmstream-win" / "vgmstream-cli.exe"
        if preferred.is_file():
            return str(preferred)
        return cls._find_tool("vgmstream-cli.exe", "vgmstream-cli")

    @classmethod
    def _find_ffmpeg(cls) -> str:
        preferred = Path(r"C:\ffmpeg\ffmpeg.exe")
        if preferred.is_file():
            return str(preferred)
        return cls._find_tool("ffmpeg.exe", "ffmpeg")

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(1, weight=1)
        outer.rowconfigure(6, weight=1)

        ttk.Label(outer, text="PCK or WEM file/folder").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(outer, textvariable=self.input_var).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(outer, text="Choose…", command=self._choose_input).grid(row=0, column=2)
        ttk.Label(outer, text="Output folder").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(outer, textvariable=self.output_var).grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(outer, text="Choose…", command=self._choose_output).grid(row=1, column=2)

        ttk.Separator(outer).grid(row=2, column=0, columnspan=3, sticky="ew", pady=10)
        ttk.Label(outer, text="vgmstream CLI (needed for WAV)").grid(row=3, column=0, sticky="w", pady=5)
        ttk.Entry(outer, textvariable=self.vgm_var).grid(row=3, column=1, sticky="ew", padx=8)
        ttk.Button(outer, text="Browse…", command=lambda: self._choose_exe(self.vgm_var)).grid(row=3, column=2)
        ttk.Label(outer, text="ffmpeg (needed for MP3)").grid(row=4, column=0, sticky="w", pady=5)
        ttk.Entry(outer, textvariable=self.ffmpeg_var).grid(row=4, column=1, sticky="ew", padx=8)
        ttk.Button(outer, text="Browse…", command=lambda: self._choose_exe(self.ffmpeg_var)).grid(row=4, column=2)

        options = ttk.Frame(outer)
        options.grid(row=5, column=0, columnspan=3, sticky="w", pady=7)
        ttk.Checkbutton(options, text="Convert WEM to WAV", variable=self.wav_var).pack(side="left", padx=(0, 18))
        ttk.Checkbutton(options, text="Convert WEM to MP3", variable=self.mp3_var).pack(side="left")
        self.start_button = ttk.Button(options, text="Extract audio", command=self._start)
        self.start_button.pack(side="left", padx=22)
        ttk.Button(options, text="Hash filename…", command=self._hash_dialog).pack(side="left", padx=10)
        self.progress = ttk.Progressbar(options, mode="indeterminate", length=150)
        self.progress.pack(side="left")

        ttk.Label(outer, text="Progress").grid(row=6, column=0, columnspan=3, sticky="sw", pady=(4, 2))
        self.log = tk.Text(outer, height=15, wrap="word", state="disabled")
        self.log.grid(row=7, column=0, columnspan=3, sticky="nsew")
        outer.rowconfigure(7, weight=1)
        ttk.Label(outer, text="Select PCK packages to extract, or decrypted WEM files to convert directly.",
                  foreground="#555").grid(row=8, column=0, columnspan=3, sticky="w", pady=(8, 0))

    def _hash_dialog(self) -> None:
        window = tk.Toplevel(self.root)
        window.title("Candidate filename hash")
        window.resizable(False, False)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Candidate name (Wwise names are typically lowercase):").pack(anchor="w")
        name_var = tk.StringVar()
        entry = ttk.Entry(frame, textvariable=name_var, width=50)
        entry.pack(fill="x", pady=8)
        result = tk.StringVar(value="FNV-1 32-bit: —\nFNV-1a 32-bit: —")
        ttk.Label(frame, textvariable=result, justify="left").pack(anchor="w", pady=5)

        def calculate() -> None:
            name = name_var.get()
            if not name:
                result.set("Enter a candidate name.")
                return
            result.set(
                f"FNV-1 32-bit:  {fnv_hash(name, 'fnv1', 32):08X}\n"
                f"FNV-1a 32-bit: {fnv_hash(name, 'fnv1a', 32):08X}\n"
                "Names are lowercased before hashing. A hash does not reveal its original name."
            )

        ttk.Button(frame, text="Calculate", command=calculate).pack(anchor="e", pady=(6, 0))
        entry.focus_set()

    def _choose_input(self) -> None:
        path = filedialog.askdirectory(title="Choose a folder containing PCK files")
        if not path:
            path = filedialog.askopenfilename(title="Choose a Wwise PCK or WEM", filetypes=[("Audio files", "*.pck *.wem"), ("Wwise PCK", "*.pck"), ("Wwise WEM", "*.wem"), ("All files", "*.*")])
        if path:
            self.input_var.set(path)

    def _choose_output(self) -> None:
        path = filedialog.askdirectory(title="Choose output folder")
        if path:
            self.output_var.set(path)

    @staticmethod
    def _choose_exe(variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(title="Choose command line executable", filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            variable.set(path)

    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _start(self) -> None:
        if self.running:
            return
        source_text = self.input_var.get().strip()
        output_text = self.output_var.get().strip()
        if not source_text or not Path(source_text).exists():
            messagebox.showerror("Missing input", "Choose a PCK file or a folder containing PCK files.")
            return
        if not output_text:
            messagebox.showerror("Missing output", "Choose an output folder.")
            return
        if (self.wav_var.get() or self.mp3_var.get()) and not Path(self.vgm_var.get()).is_file():
            messagebox.showerror("vgmstream not found", "Choose vgmstream-cli.exe to decode WEM files before conversion.")
            return
        if self.mp3_var.get() and not Path(self.ffmpeg_var.get()).is_file():
            messagebox.showerror("ffmpeg not found", "Choose ffmpeg.exe to convert WEM files to MP3.")
            return
        self.running = True
        self.start_button.configure(state="disabled")
        self.progress.start(12)
        self._log("Starting extraction…")
        threading.Thread(target=self._worker, args=(Path(source_text), Path(output_text)), daemon=True).start()

    def _worker(self, source: Path, output: Path) -> None:
        try:
            pcks = [source] if source.is_file() and source.suffix.lower() == ".pck" else ([] if source.is_file() else sorted(source.rglob("*.pck")))
            wem_files = [source] if source.is_file() and source.suffix.lower() == ".wem" else ([] if source.is_file() else sorted(source.rglob("*.wem")))
            if not pcks and not wem_files:
                raise ValueError("No .pck or .wem files were found at the selected input.")
            output.mkdir(parents=True, exist_ok=True)
            for index, pck in enumerate(pcks, 1):
                self.events.put(("log", f"[{index}/{len(pcks)}] Processing {pck.name}"))
                try:
                    count, written = extract_pck(pck, output)
                    wem_files.extend(path for path in written if path.suffix.lower() == ".wem")
                    self.events.put(("log", f"  Read {count} entries; extracted {len(written)} WEM/BNK/PLUG files."))
                except Exception as exc:
                    self.events.put(("log", f"  ERROR: {exc}"))
            converted = 0
            if self.wav_var.get() or self.mp3_var.get():
                def convert_one(wem: Path) -> int:
                    wav_path = output / (wem.stem + ".wav")
                    converted_count = 0
                    if self.wav_var.get():
                        self._run_command([self.vgm_var.get(), "-o", str(wav_path), str(wem)])
                        if wav_path.exists():
                            converted_count += 1
                    elif self.mp3_var.get():
                        with tempfile.TemporaryDirectory(prefix="endfield_audio_") as temp:
                            temp_wav = Path(temp) / (wem.stem + ".wav")
                            self._run_command([self.vgm_var.get(), "-o", str(temp_wav), str(wem)])
                            if temp_wav.exists():
                                mp3_path = output / (wem.stem + ".mp3")
                                self._convert_mp3(temp_wav, mp3_path)
                                converted_count += int(mp3_path.exists())
                    if self.wav_var.get() and self.mp3_var.get() and wav_path.exists():
                        mp3_path = output / (wem.stem + ".mp3")
                        self._convert_mp3(wav_path, mp3_path)
                        converted_count += int(mp3_path.exists())
                    return converted_count

                with ThreadPoolExecutor(max_workers=4) as pool:
                    futures = [pool.submit(convert_one, wem) for wem in wem_files]
                    for index, future in enumerate(as_completed(futures), 1):
                        converted += future.result()
                        if index % 1000 == 0 or index == len(futures):
                            self.events.put(("log", f"Converted {index:,}/{len(futures):,} WEM files."))
                summary = f"Finished. Extracted {len(wem_files)} WEM files; converted {converted} files."
            else:
                summary = f"Finished decryption. Extracted {len(wem_files)} WEM files; no conversion was selected."
            self.events.put(("done", summary))
        except Exception as exc:
            self.events.put(("done", f"Stopped: {exc}"))

    def _run_command(self, command: list[str]) -> None:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        if result.returncode:
            self.events.put(("log", f"  Converter returned {result.returncode}: {result.stdout[-800:].strip()}"))

    def _convert_mp3(self, wav: Path, mp3: Path) -> None:
        self._run_command([self.ffmpeg_var.get(), "-hide_banner", "-loglevel", "error", "-y", "-i", str(wav), "-q:a", "2", str(mp3)])

    def _poll_events(self) -> None:
        self._poll_after_id = None
        if self._closing:
            return
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "log":
                    self._log(message)
                elif kind == "done":
                    self._log(message)
                    self.progress.stop()
                    self.start_button.configure(state="normal")
                    self.running = False
        except queue.Empty:
            pass
        if not self._closing:
            try:
                self._poll_after_id = self.root.after(100, self._poll_events)
            except tk.TclError:
                self._poll_after_id = None

    def _on_close(self) -> None:
        self._closing = True
        if self._poll_after_id is not None:
            try:
                self.root.after_cancel(self._poll_after_id)
            except tk.TclError:
                pass
            self._poll_after_id = None
        try:
            self.root.destroy()
        except tk.TclError:
            pass


def signed_u32(value: int) -> int:
    value &= MASK32
    return value if value < 0x80000000 else value - 0x100000000


def safe_audio_path(value: str) -> str:
    """Return a safe game-style relative path, never an absolute/traversal path."""
    value = (value or "").replace("\\", "/").strip(" /")
    parts = [part for part in value.split("/") if part not in ("", ".", "..")]
    return "/".join(parts)


def load_audio_names(tables_dir: Path) -> dict[int, dict[str, object]]:
    """Resolve Wwise media IDs using Endfield's language-prefixed FNV-1 64-bit path hash."""
    names: dict[int, dict[str, object]] = {}
    dialog_file = tables_dir / "AudioDialog.json"
    if dialog_file.is_file():
        with dialog_file.open("r", encoding="utf-8-sig") as stream:
            rows = json.load(stream)
        for raw_key, row in rows.items():
            path = safe_audio_path(str(row.get("path", "")))
            if not path:
                continue
            stem = Path(path).stem
            try:
                legacy_id = int(raw_key) & MASK32
            except ValueError:
                legacy_id = fnv_hash(stem, "fnv1", 32)
            for language, duration_field in (
                ("chinese", "wavDuration"),
                ("english", "wavDurationEN"),
                ("japanese", "wavDurationJP"),
                ("korean", "wavDurationKR"),
            ):
                duration = row.get(duration_field) or row.get("wavDuration")
                try:
                    duration = float(duration) if duration else None
                except (TypeError, ValueError):
                    duration = None
                voice_path = f"voice/{language}/{path}".lower()
                names[fnv_hash(voice_path, "fnv1", 64)] = {
                    "path": voice_path,
                    "name": Path(path).with_suffix(".wav").name,
                    "speaker": str(row.get("speakerChannel", "")),
                    "duration": duration,
                }
            # A few legacy records use a plain 32-bit AudioDialog filename hash.
            names.setdefault(legacy_id, {
                "path": path,
                "name": Path(path).with_suffix(".wav").name,
                "speaker": str(row.get("speakerChannel", "")),
                "duration": row.get("wavDuration"),
            })

    return names


def package_language(pck: Path) -> str:
    group = pck.parent.name
    return {"Main": "Global", "Audit": "Audit", "Initial": "Initial"}.get(group, group)


def build_audio_map(source_root: Path, tables_dir: Path, map_path: Path,
                    progress: queue.Queue[tuple[str, str]]) -> tuple[int, int, list[str]]:
    """Index encrypted PCK WEM records without extracting or decoding their payloads."""
    pcks = sorted(source_root.rglob("*.pck")) if source_root.is_dir() else [source_root]
    if not pcks:
        raise ValueError(f"No PCK files found under {source_root}")
    name_map = load_audio_names(tables_dir)
    map_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="audio-map-", suffix=".map", dir=map_path.parent)
    os.close(fd)
    temp_path = Path(temp_name)
    errors: list[str] = []
    total = 0
    try:
        with closing(sqlite3.connect(temp_path)) as db:
            db.execute("PRAGMA journal_mode=OFF")
            db.execute("PRAGMA synchronous=OFF")
            db.execute("""CREATE TABLE tracks (
                id INTEGER PRIMARY KEY, source_path TEXT NOT NULL, relative_pck TEXT NOT NULL,
                language TEXT NOT NULL, file_id TEXT NOT NULL, offset INTEGER NOT NULL,
                size INTEGER NOT NULL, asset_path TEXT NOT NULL, display_name TEXT NOT NULL,
                speaker TEXT NOT NULL, duration REAL, UNIQUE(source_path,file_id,offset)
            )""")
            for index, pck in enumerate(pcks, 1):
                progress.put(("log", f"Indexing [{index}/{len(pcks)}] {pck.relative_to(source_root) if source_root.is_dir() else pck.name}"))
                try:
                    file_size = pck.stat().st_size
                    with pck.open("rb") as package:
                        prefix = package.read(8)
                        if len(prefix) < 8:
                            raise ValueError("short PCK")
                        header_size = struct.unpack_from("<I", prefix, 4)[0]
                        header_end = 8 + header_size
                        if header_size > 512 * 1024 * 1024 or header_end > file_size:
                            raise ValueError("invalid PCK header size")
                        package.seek(0)
                        header, header_end = decrypt_pck_header(package.read(header_end))
                        entries = parse_entries(header, file_size=file_size, header_end=header_end)
                        rows = []
                        for file_id, offset, size in entries:
                            if size < 4 or offset < header_end or offset + size > file_size:
                                continue
                            package.seek(offset)
                            signature = package.read(4)
                            if signature != b"RIFF" and decipher(signature, file_id & MASK32) != b"RIFF":
                                continue
                            media = name_map.get(file_id) or name_map.get(file_id & MASK32) or {}
                            asset_path = safe_audio_path(str(media.get("path", "")))
                            if not asset_path or not asset_path.lower().endswith(".wem"):
                                asset_path = f"Unmapped/{file_id:08X}.wem"
                            display_name = str(media.get("name", Path(asset_path).with_suffix(".wav").name))
                            rows.append((str(pck.resolve()),
                                pck.relative_to(source_root).as_posix() if source_root.is_dir() else pck.name,
                                package_language(pck), str(file_id), int(offset), int(size), asset_path,
                                display_name, str(media.get("speaker", "")),
                                media.get("duration")))
                    db.executemany("""INSERT OR IGNORE INTO tracks
                        (source_path,relative_pck,language,file_id,offset,size,asset_path,display_name,speaker,duration)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""", rows)
                    total += len(rows)
                except Exception as exc:
                    errors.append(f"{pck.name}: {exc}")
                    progress.put(("log", f"  Skipped {pck.name}: {exc}"))
            db.execute("CREATE INDEX tracks_search ON tracks(language,display_name,asset_path,speaker,file_id)")
            db.commit()
        for attempt in range(4):
            try:
                os.replace(temp_path, map_path)
                break
            except PermissionError as exc:
                if attempt == 3:
                    raise PermissionError(
                        f"Windows could not replace {map_path.name}. Close other Audio Extractor windows "
                        "or programs using this map, wait for OneDrive to finish syncing, then retry."
                    ) from exc
                time.sleep(0.25 * (attempt + 1))
    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return total, len(pcks), errors


def row_mp3_path(output_root: Path, language: str, asset_path: str, file_id: int,
                 add_language_prefix: bool = True) -> Path:
    relative = Path(*safe_audio_path(asset_path).split("/"))
    if relative.is_absolute() or ".." in relative.parts:
        relative = Path(f"Unmapped/{file_id:08X}.wem")
    if relative.suffix.lower() == ".wem":
        relative = relative.with_suffix(".mp3")
    else:
        relative = relative.with_name(relative.name + ".mp3")
    lang = safe_audio_path(language) or "Other"
    language_prefixes = {
        "english": "EN_",
        "chinese": "CN_",
        "japanese": "JP_",
        "korean": "KR_",
    }
    prefix = language_prefixes.get(lang.casefold(), "") if add_language_prefix else ""
    if prefix and not relative.name.casefold().startswith(prefix.casefold()):
        relative = relative.with_name(prefix + relative.name)
    if relative.parts and relative.parts[0].lower() == "voice":
        return output_root / relative
    return output_root / lang / relative


def export_mp3(source_path: Path, offset: int, size: int, file_id: int, destination: Path,
               vgmstream: str, ffmpeg: str) -> None:
    """Decrypt and convert one selected WEM; only the final validated MP3 persists."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source_path.open("rb") as package:
        package.seek(offset)
        encrypted = package.read(size)
    if len(encrypted) != size:
        raise ValueError("Could not read the complete WEM record from its PCK")
    wem = encrypted if encrypted.startswith(b"RIFF") else decipher(encrypted, file_id & MASK32)
    if not wem.startswith(b"RIFF"):
        raise ValueError("Decryption did not produce a RIFF/WEM stream")
    with tempfile.TemporaryDirectory(prefix="endfield_audio_") as temp:
        temp_dir = Path(temp)
        wem_path, wav_path, mp3_path = temp_dir / "selected.wem", temp_dir / "decoded.wav", temp_dir / "selected.mp3"
        wem_path.write_bytes(wem)
        decoded = subprocess.run([vgmstream, "-o", str(wav_path), str(wem_path)],
                                 capture_output=True, text=True, errors="replace")
        if decoded.returncode or not wav_path.is_file() or wav_path.stat().st_size < 44:
            raise RuntimeError((decoded.stderr or decoded.stdout or "vgmstream failed").strip()[-1200:])
        converted = subprocess.run([ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-i", str(wav_path),
                                    "-map", "0:a:0", "-codec:a", "libmp3lame", "-q:a", "2", str(mp3_path)],
                                   capture_output=True, text=True, errors="replace")
        if converted.returncode or not mp3_path.is_file() or mp3_path.stat().st_size < 128:
            raise RuntimeError((converted.stderr or converted.stdout or "FFmpeg MP3 conversion failed").strip()[-1200:])
        validation = subprocess.run([ffmpeg, "-hide_banner", "-v", "error", "-i", str(mp3_path), "-f", "null", "-"],
                                    capture_output=True, text=True, errors="replace")
        if validation.returncode:
            raise RuntimeError((validation.stderr or "MP3 validation failed").strip()[-1200:])
        staged = destination.with_name(destination.name + ".tmp")
        shutil.copyfile(mp3_path, staged)
        os.replace(staged, destination)


def decode_preview(source_path: Path, offset: int, size: int, file_id: int,
                   vgmstream: str, temp_dir: Path) -> tuple[Path, float]:
    """Decrypt and decode one selected WEM to a temporary WAV for preview."""
    with source_path.open("rb") as package:
        package.seek(offset)
        encrypted = package.read(size)
    if len(encrypted) != size:
        raise ValueError("Could not read the complete WEM record from its PCK")
    wem = encrypted if encrypted.startswith(b"RIFF") else decipher(encrypted, file_id & MASK32)
    if not wem.startswith(b"RIFF"):
        raise ValueError("Decryption did not produce a RIFF/WEM stream")
    wem_path, wav_path = temp_dir / "preview.wem", temp_dir / "preview.wav"
    wem_path.write_bytes(wem)
    decoded = subprocess.run([vgmstream, "-o", str(wav_path), str(wem_path)],
                             capture_output=True, text=True, errors="replace")
    if decoded.returncode or not wav_path.is_file() or wav_path.stat().st_size < 44:
        raise RuntimeError((decoded.stderr or decoded.stdout or "vgmstream failed").strip()[-1200:])
    with wave.open(str(wav_path), "rb") as wav:
        sample_rate = wav.getframerate()
        if sample_rate <= 0:
            raise RuntimeError("vgmstream produced a WAV with an invalid sample rate")
        duration = wav.getnframes() / sample_rate
    return wav_path, duration


class AudioCatalogApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Endfield Audio Catalog and Extractor")
        root.geometry("1120x700")
        root.minsize(900, 560)
        self.events: queue.Queue[tuple[str, str]] = queue.Queue()
        self.running = False
        self._closing = False
        self._poll_after_id: str | None = None
        self._refresh_after_id: str | None = None
        self.page_size = 1000
        self.page = 0
        self.match_count = 0
        self.preview_dir: Path | None = None
        self.preview_token = 0
        self.preview_started_at: float | None = None
        self.preview_duration = 0.0
        base = Path(__file__).resolve().parents[1]
        self.source_var = tk.StringVar(value=str(base / "Audio raw"))
        self.tables_var = tk.StringVar(value=str(base / "input" / "TableCfgOutput"))
        self.output_var = tk.StringVar(value=str(base / "Audio output"))
        self.vgm_var = tk.StringVar(value=AudioExtractorApp._find_vgmstream())
        self.ffmpeg_var = tk.StringVar(value=AudioExtractorApp._find_ffmpeg())
        self.search_var = tk.StringVar()
        self.language_var = tk.StringVar(value="All")
        self.visible_rows: dict[str, tuple] = {}
        self._build_ui()
        self._poll_after_id = self.root.after(100, self._poll_events)
        self._refresh_after_id = self.root.after(500, self._run_scheduled_refresh)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill="both", expand=True)
        for col in (1,):
            frame.columnconfigure(col, weight=1)
        frame.rowconfigure(8, weight=1)
        fields = [("PCK source", self.source_var), ("Game tables", self.tables_var),
                  ("MP3 output", self.output_var), ("vgmstream", self.vgm_var), ("FFmpeg", self.ffmpeg_var)]
        for i, (label, var) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky="w", pady=2)
            ttk.Entry(frame, textvariable=var).grid(row=i, column=1, sticky="ew", padx=7, pady=2)
            if i < 3:
                command = lambda v=var: v.set(filedialog.askdirectory() or v.get())
            else:
                command = lambda v=var: AudioExtractorApp._choose_exe(v)
            ttk.Button(frame, text="Browse…", command=command).grid(row=i, column=2, sticky="ew", pady=2)
        ttk.Button(frame, text="Build / refresh audio.map", command=self.start_index).grid(row=0, column=3, padx=(8, 0))
        ttk.Separator(frame).grid(row=5, column=0, columnspan=4, sticky="ew", pady=8)
        ttk.Label(frame, text="Search filename, folder, speaker, ID:").grid(row=6, column=0, sticky="w")
        search = ttk.Entry(frame, textvariable=self.search_var)
        search.grid(row=6, column=1, sticky="ew", padx=7)
        self.lang_box = ttk.Combobox(frame, textvariable=self.language_var, state="readonly", values=["All"])
        self.lang_box.grid(row=6, column=2, sticky="ew")
        ttk.Button(frame, text="Export / repair selected MP3", command=self.export_selected).grid(row=6, column=3, padx=(8, 0))
        ttk.Button(frame, text="Preview selected", command=self.preview_selected).grid(row=6, column=4, padx=(6, 0))
        ttk.Button(frame, text="Stop preview", command=self.stop_preview).grid(row=6, column=5, padx=(6, 0))
        columns = ("language", "name", "directory", "speaker", "duration", "size", "id", "status")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="extended")
        headings = {"language":"Language", "name":"Real filename", "directory":"Game folder", "speaker":"Speaker", "duration":"Seconds", "size":"Bytes", "id":"Wwise ID", "status":"MP3"}
        widths = {"language":90, "name":260, "directory":300, "speaker":120, "duration":75, "size":85, "id":95, "status":65}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w" if col in ("name", "directory", "speaker", "language") else "center")
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.hide_unmapped_var = tk.BooleanVar(value=True)
        self.language_prefix_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Hide unmapped Wwise IDs", variable=self.hide_unmapped_var,
                        command=self._reset_and_refresh).grid(row=7, column=0, sticky="w", pady=(4, 0))
        ttk.Checkbutton(frame, text="Add language prefixes to exports", variable=self.language_prefix_var
                        ).grid(row=7, column=4, sticky="w", padx=6, pady=(4, 0))
        self.preview_time_var = tk.StringVar(value="Preview: —")
        ttk.Label(frame, textvariable=self.preview_time_var).grid(
            row=7, column=1, columnspan=3, sticky="w", padx=7, pady=(4, 0))
        self.tree.grid(row=8, column=0, columnspan=5, sticky="nsew")
        yscroll.grid(row=8, column=5, sticky="ns")
        xscroll.grid(row=9, column=0, columnspan=5, sticky="ew")
        nav = ttk.Frame(frame)
        nav.grid(row=9, column=5, sticky="e", padx=(5, 0))
        self.prev_button = ttk.Button(nav, text="◀ Previous", command=self._previous_page)
        self.prev_button.pack(side="left")
        self.page_label = ttk.Label(nav, text="Page 0 / 0", width=14, anchor="center")
        self.page_label.pack(side="left", padx=4)
        self.next_button = ttk.Button(nav, text="Next ▶", command=self._next_page)
        self.next_button.pack(side="left")
        self.status = tk.StringVar(value="Build the map to index WEM names from your PCKs.")
        ttk.Label(frame, textvariable=self.status).grid(row=10, column=0, columnspan=6, sticky="w", pady=(5, 2))
        self.log = tk.Text(frame, height=5, wrap="word", state="disabled")
        self.log.grid(row=11, column=0, columnspan=6, sticky="ew")
        self.search_var.trace_add("write", lambda *_: self._reset_and_refresh())
        self.lang_box.bind("<<ComboboxSelected>>", lambda _e: self._reset_and_refresh())

    def _reset_and_refresh(self) -> None:
        if self._closing:
            return
        self.page = 0
        self._cancel_after("_refresh_after_id")
        try:
            self._refresh_after_id = self.root.after(200, self._run_scheduled_refresh)
        except tk.TclError:
            self._refresh_after_id = None

    def _run_scheduled_refresh(self) -> None:
        self._refresh_after_id = None
        if not self._closing:
            self.refresh_catalog()

    def _cancel_after(self, attribute: str) -> None:
        callback_id = getattr(self, attribute, None)
        if callback_id is None:
            return
        try:
            self.root.after_cancel(callback_id)
        except tk.TclError:
            pass
        setattr(self, attribute, None)

    def _previous_page(self) -> None:
        if self.page > 0:
            self.page -= 1
            self.refresh_catalog()

    def _next_page(self) -> None:
        if (self.page + 1) * self.page_size < self.match_count:
            self.page += 1
            self.refresh_catalog()

    def map_path(self) -> Path:
        return Path(self.output_var.get()) / "audio.map"

    def refresh_catalog(self) -> None:
        map_path = self.map_path()
        if not map_path.is_file() or self.running:
            return
        try:
            needle = self.search_var.get().strip()
            language = self.language_var.get()
            with closing(sqlite3.connect(map_path)) as db:
                languages = [row[0] for row in db.execute("SELECT DISTINCT language FROM tracks ORDER BY language")]
                values = ["All"] + languages
                if tuple(self.lang_box["values"]) != tuple(values):
                    self.lang_box["values"] = values
                clauses, args = [], []
                if language != "All":
                    clauses.append("language=?"); args.append(language)
                if self.hide_unmapped_var.get():
                    clauses.append("asset_path NOT LIKE 'Unmapped/%'")
                if needle:
                    clauses.append("(display_name LIKE ? OR asset_path LIKE ? OR speaker LIKE ? OR file_id LIKE ? OR file_id=?)")
                    pattern = f"%{needle}%"
                    try:
                        hex_text = needle[2:] if needle.lower().startswith("0x") else needle
                        exact_id = str(int(hex_text, 16))
                    except ValueError:
                        exact_id = ""
                    args.extend([pattern, pattern, pattern, pattern, exact_id])
                where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
                count = db.execute("SELECT count(*) FROM tracks" + where, args).fetchone()[0]
                pages = (count + self.page_size - 1) // self.page_size
                if pages and self.page >= pages:
                    self.page = pages - 1
                db.create_collation("NATURAL_SORT", natural_sort_compare)
                rows = db.execute("SELECT id,language,display_name,asset_path,speaker,duration,size,file_id,source_path,offset,relative_pck FROM tracks" + where + " ORDER BY language,display_name COLLATE NATURAL_SORT,asset_path COLLATE NATURAL_SORT,file_id LIMIT ? OFFSET ?", [*args, self.page_size, self.page * self.page_size]).fetchall()
            self.match_count = count
            self.page_label.configure(text=f"Page {self.page + 1 if count else 0} / {pages}")
            self.prev_button.configure(state="normal" if self.page > 0 else "disabled")
            self.next_button.configure(state="normal" if (self.page + 1) * self.page_size < count else "disabled")
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.visible_rows.clear()
            output = Path(self.output_var.get())
            for row in rows:
                key, lang, name, asset, speaker, duration, size, file_id, *_ = row
                numeric_id = int(file_id)
                uid = str(key); self.visible_rows[uid] = row
                destination = row_mp3_path(output, lang, asset, numeric_id, self.language_prefix_var.get())
                status = "Ready" if destination.is_file() else "—"
                if not asset.startswith("Unmapped/"):
                    name = Path(asset).with_suffix(".wav").name
                directory = str(Path(asset).parent).replace("\\", "/")
                self.tree.insert("", "end", iid=uid, values=(lang, name, directory, speaker,
                    f"{duration:.2f}" if duration else "", f"{size:,}", f"{numeric_id:08X}", status))
            first = self.page * self.page_size + 1 if rows else 0
            last = self.page * self.page_size + len(rows)
            self.status.set(f"{count:,} matches; showing {first:,}–{last:,}. Map: {map_path.name}")
        except (sqlite3.Error, OSError) as exc:
            self.status.set(f"Could not read audio.map: {exc}")

    def _log(self, message: str) -> None:
        self.log.configure(state="normal"); self.log.insert("end", message + "\n"); self.log.see("end"); self.log.configure(state="disabled")

    def start_index(self) -> None:
        if self.running:
            return
        source, tables, out = Path(self.source_var.get()), Path(self.tables_var.get()), Path(self.output_var.get())
        if not source.exists() or not tables.is_dir():
            messagebox.showerror("Missing source", "Choose the Audio raw PCK folder and extracted TableCfgOutput folder.")
            return
        self.running = True
        threading.Thread(target=self._index_worker, args=(source, tables, out), daemon=True).start()

    def _index_worker(self, source: Path, tables: Path, output: Path) -> None:
        try:
            count, packages, errors = build_audio_map(source, tables, output / "audio.map", self.events)
            self.events.put(("done", f"Map ready: {count:,} WEM entries across {packages} PCKs. {len(errors)} package errors."))
        except Exception as exc:
            self.events.put(("done", f"Map build failed: {exc}"))

    def export_selected(self) -> None:
        if self.running:
            return
        selected = [self.visible_rows[iid] for iid in self.tree.selection() if iid in self.visible_rows]
        if not selected:
            messagebox.showinfo("Select audio", "Select one or more rows from the mapped list first.")
            return
        if not Path(self.vgm_var.get()).is_file() or not Path(self.ffmpeg_var.get()).is_file():
            messagebox.showerror("Converter missing", "Choose vgmstream-cli.exe and ffmpeg.exe before exporting MP3.")
            return
        self.running = True
        threading.Thread(target=self._export_worker, args=(selected,), daemon=True).start()

    def preview_selected(self) -> None:
        if self.running:
            return
        selected_ids = self.tree.selection()
        if not selected_ids or selected_ids[0] not in self.visible_rows:
            messagebox.showinfo("Select audio", "Select one audio row to preview.")
            return
        if not Path(self.vgm_var.get()).is_file():
            messagebox.showerror("Decoder missing", "Choose vgmstream-cli.exe before previewing audio.")
            return
        self.stop_preview()
        self.running = True
        row = self.visible_rows[selected_ids[0]]
        temp_dir = Path(tempfile.mkdtemp(prefix="endfield_preview_"))
        self.preview_dir = temp_dir
        token = self.preview_token
        threading.Thread(target=self._preview_worker, args=(row, temp_dir, token), daemon=True).start()

    def _preview_worker(self, row: tuple, temp_dir: Path, token: int) -> None:
        try:
            _key, _language, name, _asset, _speaker, _duration, size, file_id, source_path, offset, _relative = row
            wav_path, duration = decode_preview(
                Path(source_path), offset, size, int(file_id), self.vgm_var.get(), temp_dir)
            self.events.put(("preview_ready", f"{token}\t{wav_path}\t{duration:.6f}"))
            self.events.put(("preview_dir", f"{token}\t{temp_dir}"))
            self.events.put(("done", f"Previewing {name}"))
        except Exception as exc:
            shutil.rmtree(temp_dir, ignore_errors=True)
            self.events.put(("done", f"Preview failed: {exc}"))

    def stop_preview(self) -> None:
        self.preview_token += 1
        try:
            import winsound
            winsound.PlaySound(None, winsound.SND_PURGE)
        except (ImportError, RuntimeError):
            pass
        if self.preview_dir:
            shutil.rmtree(self.preview_dir, ignore_errors=True)
            self.preview_dir = None
        self.preview_started_at = None
        self.preview_duration = 0.0
        self.preview_time_var.set("Preview: stopped")

    def _on_close(self) -> None:
        self._closing = True
        self._cancel_after("_poll_after_id")
        self._cancel_after("_refresh_after_id")
        self.stop_preview()
        try:
            self.root.destroy()
        except tk.TclError:
            pass

    def _export_worker(self, rows: list[tuple]) -> None:
        ok = failed = 0
        output = Path(self.output_var.get())
        for index, row in enumerate(rows, 1):
            _, language, name, asset, _speaker, _duration, size, file_id, source_path, offset, _relative = row
            file_id = int(file_id)
            destination = row_mp3_path(output, language, asset, file_id, self.language_prefix_var.get())
            try:
                export_mp3(Path(source_path), offset, size, file_id, destination, self.vgm_var.get(), self.ffmpeg_var.get())
                ok += 1
                self.events.put(("log", f"Exported {language}/{asset}"))
            except Exception as exc:
                failed += 1
                self.events.put(("log", f"FAILED {name} [{file_id:08X}]: {exc}"))
            if index % 25 == 0 or index == len(rows):
                self.events.put(("status", f"Exported {index:,}/{len(rows):,} selected files…"))
        self.events.put(("done", f"Finished MP3 export/repair: {ok} succeeded, {failed} failed."))

    def _poll_events(self) -> None:
        self._poll_after_id = None
        if self._closing:
            return
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "log": self._log(message)
                elif kind == "status": self.status.set(message)
                elif kind == "preview_dir":
                    token_text, directory = message.split("\t", 1)
                    if int(token_text) == self.preview_token:
                        self.preview_dir = Path(directory)
                    else:
                        shutil.rmtree(directory, ignore_errors=True)
                elif kind == "preview_ready":
                    token_text, wav_path, duration_text = message.split("\t", 2)
                    if int(token_text) == self.preview_token:
                        try:
                            import winsound
                            winsound.PlaySound(wav_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                            self.preview_duration = float(duration_text)
                            self.preview_started_at = time.monotonic()
                            self._update_preview_countdown()
                        except (ImportError, RuntimeError) as exc:
                            self._log(f"Preview playback unavailable: {exc}")
                elif kind == "done":
                    self._log(message); self.running = False; self.refresh_catalog()
        except queue.Empty:
            pass
        if not self._closing:
            self._update_preview_countdown()
            try:
                self._poll_after_id = self.root.after(100, self._poll_events)
            except tk.TclError:
                self._poll_after_id = None

    def _update_preview_countdown(self) -> None:
        if self.preview_started_at is None:
            return
        remaining = max(0.0, self.preview_duration - (time.monotonic() - self.preview_started_at))
        seconds = int(remaining + 0.999)
        self.preview_time_var.set(f"Preview remaining: {seconds // 60:02d}:{seconds % 60:02d}")
        if remaining <= 0:
            try:
                import winsound
                winsound.PlaySound(None, winsound.SND_PURGE)
            except (ImportError, RuntimeError):
                pass
            if self.preview_dir:
                shutil.rmtree(self.preview_dir, ignore_errors=True)
                self.preview_dir = None
            self.preview_started_at = None
            self.preview_duration = 0.0
            self.preview_time_var.set("Preview: finished")


def main() -> None:
    root = tk.Tk()
    AudioCatalogApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
