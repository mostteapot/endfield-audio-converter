# Endfield Audio Catalog and Extractor

A Windows Python/Tkinter tool for indexing Endfield Wwise PCKs, looking up real voice filenames from extracted game tables, and exporting only selected MP3s.

## Run
0. Extract audio files from the game using BeyondTools.
1. Install Python 3.10 or later. NumPy is optional and speeds up decryption (`python -m pip install numpy`).
2. Install vgmstream CLI and FFmpeg. The app looks for `Downloads\vgmstream-win\vgmstream-cli.exe` and `C:\ffmpeg\ffmpeg.exe`, and provides Browse buttons if they are elsewhere.
3. Run `python audio_extractor.py` from this folder.
4. Keep the default paths if your `Audio raw` PCKs and `input\TableCfgOutput` tables are in the parent project folder. Click **Build / refresh audio.map**.
5. Search by filename, game folder, speaker, or Wwise ID. Unmapped Wwise-ID rows are hidden by default; uncheck **Hide unmapped Wwise IDs** to show them. Use **Previous / Next** to page through every match (1,000 rows per page). Names sort naturally, so `_2_` comes before `_11_`. Select a row and click **Preview selected** to listen, or select one or more rows and click **Export / repair selected MP3**.

The map is a compact SQLite database named `Audio output\audio.map`. It stores PCK path, language, WEM ID, byte offset and size, resolved game path, filename, speaker, and known duration. Building the map reads the PCK headers and small entry signatures; it does not extract every WEM or convert the full game audio. English, Chinese, Japanese, Korean, Global, Initial, and Audit PCK folders are indexed when present.

The tool builds its filename map from `AudioDialog.json`. Localized WEM IDs are matched against the 64-bit FNV-1 hash of the lowercase path `voice/<language>/<AudioDialog path>`; matching paths retain that directory in the MP3 output. Legacy 32-bit filename hashes are also checked. Entries without a matching name remain browsable under `Unmapped` with their Wwise ID. The PCK payload cipher uses the low 32 bits of the entry ID as its seed.

Mapped rows show the intended `.wav` filename from the game path; MP3 export keeps that basename and writes `.mp3`. The **Add language prefixes to exports** checkbutton is enabled by default. When enabled, English, Chinese, Japanese, and Korean MP3s get `EN_`, `CN_`, `JP_`, or `KR_` before the basename; other folders are unchanged. The prefix affects exported MP3 filenames only. Export decrypts the selected WEM to a temporary location, decodes it with vgmstream, converts it with FFmpeg, validates the MP3, and saves only that MP3 under `Audio output\voice\<language>\<game folder>`. Re-exporting a selected row overwrites that MP3, which can repair an older bad conversion. Intermediate WEM and WAV files are temporary and removed after conversion.

Preview decrypts and decodes only the selected WEM to a temporary WAV, then plays it asynchronously through the Windows audio player. The UI shows the remaining time while it plays. **Stop preview** stops playback and removes the temporary audio. A new preview also replaces and cleans up the previous preview.

## Notes

- The input PCKs should already be extracted from VFS CHK containers by BeyondToolsMod or another VFS extractor.
- For a voice file, the catalog can show the actual in-game `.wem` path. Some non-dialogue sound effects, music, and newer content may not have a filename entry in the available table and will show an `Unmapped` path.
- vgmstream TXTP files can join multiple streams as ordered segments or simultaneous layers, but they are playlists, not name maps. They help only after bank data establishes the exact members and order; the catalog does not guess those relationships.
- The PCK cipher/parser supports observed 32-bit and 64-bit table formats. Game updates may change these structures; errors for individual packages are written to the app log.
- The PCK cipher algorithm is based on the public Endfield CBT3 reverse engineering write-up by Harry Huang: [PCK file decryption](https://blog.harryh.cn/Reverse-Engineering/Endfield-CBT3-Reverse-Engineering-2-PCK-Files-Decryption/). The article is licensed CC BY-NC-SA 4.0; review that license if redistributing adapted code.

## Optional executable packaging

```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --windowed audio_extractor.py
```

The executable is written under `dist`.
