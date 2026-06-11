"""Mini consola gráfica de WorkDRAG (sin ventana de terminal)."""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText


class WorkDragMiniApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("WorkDRAG Mini Console")
        self.root.geometry("920x620")
        self.root.minsize(780, 520)

        self.log_queue: queue.Queue[str] = queue.Queue()
        self.proc: subprocess.Popen | None = None

        self.base_dir = self._resolve_base_dir()
        self.python_exe = self.base_dir / "python_portable" / "python.exe"
        self.main_py = self.base_dir / "main.py"
        self.ui_server_py = self.base_dir / "ui" / "server.py"

        self._build_ui()
        self._tick_log_queue()
        self._log("WorkDRAG mini consola lista.\n")
        self._log(f"Base: {self.base_dir}")

    def _resolve_base_dir(self) -> Path:
        if getattr(sys, "frozen", False):
            return Path(sys.executable).resolve().parent
        return Path(__file__).resolve().parent

    def _build_ui(self) -> None:
        frm = ttk.Frame(self.root, padding=12)
        frm.pack(fill="both", expand=True)

        header = ttk.Label(
            frm,
            text="Ternura radical + auditoría sin CLI visible",
            font=("Segoe UI", 12, "bold"),
        )
        header.pack(anchor="w", pady=(0, 10))

        controls = ttk.LabelFrame(frm, text="Ejecutar auditoría", padding=10)
        controls.pack(fill="x", pady=(0, 10))

        self.mode_var = tk.StringVar(value="completa")
        ttk.Radiobutton(
            controls,
            text="Completa (default)",
            value="completa",
            variable=self.mode_var,
        ).grid(row=0, column=0, sticky="w")

        ttk.Radiobutton(
            controls,
            text="Espejo + carta coevolutiva",
            value="mirror_letter",
            variable=self.mode_var,
        ).grid(row=0, column=1, sticky="w", padx=(18, 0))

        ttk.Label(controls, text="Sector").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.sector_var = tk.StringVar(value="tecnologia")
        ttk.Entry(controls, textvariable=self.sector_var, width=30).grid(
            row=2, column=0, sticky="w"
        )

        ttk.Label(controls, text="Tamaño empresa").grid(row=1, column=1, sticky="w", pady=(10, 0), padx=(18, 0))
        self.company_size_var = tk.StringVar(value="multinacional")
        company_combo = ttk.Combobox(
            controls,
            textvariable=self.company_size_var,
            state="readonly",
            values=["pyme", "mediana", "grande", "multinacional"],
            width=18,
        )
        company_combo.grid(row=2, column=1, sticky="w", padx=(18, 0))

        self.no_shield_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            controls,
            text="Sin escudo emocional (modo avanzado)",
            variable=self.no_shield_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(10, 0))

        actions = ttk.Frame(frm)
        actions.pack(fill="x", pady=(0, 10))

        self.run_btn = ttk.Button(actions, text="Iniciar auditoría", command=self.run_audit)
        self.run_btn.pack(side="left")

        self.stop_btn = ttk.Button(actions, text="Detener", command=self.stop_audit, state="disabled")
        self.stop_btn.pack(side="left", padx=(8, 0))

        ttk.Button(actions, text="Abrir carpeta de resultados", command=self.open_exports).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(actions, text="Abrir dashboard web", command=self.open_dashboard).pack(
            side="left", padx=(8, 0)
        )

        log_frame = ttk.LabelFrame(frm, text="Actividad", padding=8)
        log_frame.pack(fill="both", expand=True)

        self.log_text = ScrolledText(log_frame, wrap="word", font=("Consolas", 10), height=20)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def _creation_flags(self) -> int:
        flags = 0
        if hasattr(subprocess, "CREATE_NO_WINDOW"):
            flags |= subprocess.CREATE_NO_WINDOW
        return flags

    def _log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _tick_log_queue(self) -> None:
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self._log(msg)
        except queue.Empty:
            pass
        self.root.after(120, self._tick_log_queue)

    def _set_running(self, running: bool) -> None:
        self.run_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _run_in_thread(self, cmd: list[str], title: str) -> None:
        def _worker() -> None:
            try:
                self.log_queue.put(f"▶ {title}")
                self.log_queue.put(f"Comando interno: {' '.join(cmd[1:])}")
                self.proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.base_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=self._creation_flags(),
                )

                assert self.proc.stdout is not None
                for line in self.proc.stdout:
                    self.log_queue.put(line.rstrip("\n"))

                rc = self.proc.wait()
                if rc == 0:
                    self.log_queue.put("✅ Auditoría completada correctamente.")
                else:
                    self.log_queue.put(f"❌ Proceso terminado con código {rc}.")
            except Exception as exc:
                self.log_queue.put(f"❌ Error: {exc}")
            finally:
                self.proc = None
                self.root.after(0, lambda: self._set_running(False))

        self._set_running(True)
        threading.Thread(target=_worker, daemon=True).start()

    def _build_cmd(self) -> tuple[list[str], str]:
        if not self.python_exe.exists():
            raise FileNotFoundError(
                "No se encontró python_portable\\python.exe."
                "\nCopia la carpeta completa del proyecto (incluyendo python_portable)."
            )
        if not self.main_py.exists():
            raise FileNotFoundError("No se encontró main.py en la carpeta del proyecto.")

        mode = self.mode_var.get()
        cmd = [str(self.python_exe), str(self.main_py), "--no-interactive"]
        title = "Auditoría completa"

        if self.no_shield_var.get():
            cmd += ["--no-shield"]

        if mode == "mirror_letter":
            sector = (self.sector_var.get() or "no_especificado").strip()
            company_size = (self.company_size_var.get() or "multinacional").strip()
            cmd += [
                "--mirror",
                "--letter",
                "--letter-tone",
                "coevolutivo",
                "--sector",
                sector,
                "--company-size",
                company_size,
            ]
            title = "Auditoría + espejo + carta"

        return cmd, title

    def run_audit(self) -> None:
        if self.proc is not None:
            messagebox.showinfo("WorkDRAG", "Ya hay una auditoría en ejecución.")
            return

        try:
            cmd, title = self._build_cmd()
        except Exception as exc:
            messagebox.showerror("WorkDRAG", str(exc))
            return

        self._run_in_thread(cmd, title)

    def stop_audit(self) -> None:
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.log_queue.put("⏹ Solicitud de detención enviada.")
        except Exception as exc:
            self.log_queue.put(f"❌ No se pudo detener: {exc}")

    def open_exports(self) -> None:
        exports = self.base_dir / "exports"
        exports.mkdir(exist_ok=True)
        try:
            subprocess.Popen(["explorer", str(exports)], creationflags=self._creation_flags())
        except Exception as exc:
            messagebox.showerror("WorkDRAG", f"No se pudo abrir exports: {exc}")

    def open_dashboard(self) -> None:
        if not self.python_exe.exists() or not self.ui_server_py.exists():
            messagebox.showerror(
                "WorkDRAG",
                "No se encontró python_portable o ui/server.py para abrir dashboard.",
            )
            return

        def _start_server() -> None:
            cmd = [str(self.python_exe), str(self.ui_server_py)]
            try:
                subprocess.Popen(
                    cmd,
                    cwd=str(self.base_dir),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=self._creation_flags(),
                )
            except Exception as exc:
                self.log_queue.put(f"❌ No se pudo iniciar dashboard: {exc}")
                return
            self.log_queue.put("🌐 Dashboard iniciándose en http://localhost:5050")
            webbrowser.open("http://localhost:5050")

        threading.Thread(target=_start_server, daemon=True).start()


def main() -> None:
    root = tk.Tk()
    style = ttk.Style(root)
    if "vista" in style.theme_names():
        style.theme_use("vista")
    app = WorkDragMiniApp(root)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
