#!/usr/bin/env python3
"""
Audeze Mobius — USB Reset Loop Monitor & Timing Profiler
---------------------------------------------------------
Quando o firmware tá corrompido, o device entra num padrão:
  CONNECT → [boot parcial] → DISCONNECT → [wait] → CONNECT → ...

Esse script:
  1. Mede o ciclo exato (quanto tempo fica up, quanto fica down)
  2. Detecta em qual fase o bootloader vs aplicação estão vivos
  3. Tenta ação automatizada na janela correta
  4. Exporta timeline para análise

Informa o melhor momento para tentar DFU ou HID commands.
"""

import subprocess, time, sys, json, re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path
from collections import deque

@dataclass
class USBEvent:
    ts: float
    action: str   # 'connect' | 'disconnect'
    vid: str
    pid: str
    busnum: str
    devnum: str
    product: str = ""

    @property
    def label(self) -> str:
        name = self.product or f"VID:{self.vid} PID:{self.pid}"
        return f"[{self.action.upper():12s}] {name} @ Bus{self.busnum} Dev{self.devnum}"


def parse_udevadm_line(line: str, ts: float) -> Optional[USBEvent]:
    """Parseia linha do `udevadm monitor --kernel --udev`."""
    # Filtra só eventos de USB de interesse
    if not ('usb' in line.lower() or 'UDEV' in line):
        return None

    action = None
    if 'add' in line or 'bind' in line:
        action = 'connect'
    elif 'remove' in line or 'unbind' in line:
        action = 'disconnect'
    else:
        return None

    # Tenta extrair VID/PID do path (formato: .../1-1.2:1.0 etc)
    vid = pid = busnum = devnum = "????"

    # lsusb snapshot no momento do evento
    try:
        result = subprocess.run(['lsusb'], capture_output=True, text=True, timeout=1)
        for dev_line in result.stdout.splitlines():
            if '22d9' in dev_line.lower() or 'audeze' in dev_line.lower() or 'mobius' in dev_line.lower():
                parts = dev_line.split()
                busnum = parts[1] if len(parts) > 1 else '??'
                devnum = parts[3].rstrip(':') if len(parts) > 3 else '??'
                vid_pid = parts[5] if len(parts) > 5 else '????:????'
                vid, pid = vid_pid.split(':') if ':' in vid_pid else ('????', '????')
                product = ' '.join(parts[6:]) if len(parts) > 6 else ''
                return USBEvent(ts=ts, action=action, vid=vid, pid=pid,
                               busnum=busnum, devnum=devnum, product=product)
    except:
        pass

    return USBEvent(ts=ts, action=action, vid=vid, pid=pid,
                   busnum=busnum, devnum=devnum)


def monitor_reset_loop(
    duration: float = 120.0,
    output: Optional[Path] = None,
    auto_action: bool = False,
):
    """
    Monitora o ciclo de reset e constrói um perfil de timing.
    """
    print("=== Audeze Mobius Reset Loop Monitor ===")
    print(f"Duração: {duration:.0f}s | Auto-action: {auto_action}")
    print()
    print("Aguardando eventos USB... (Ctrl+C para parar e ver relatório)")
    print()

    events: list[USBEvent] = []
    connect_times: list[float] = []
    disconnect_times: list[float] = []
    window_durations: list[float] = []

    start_ts = time.monotonic()
    last_connect_ts: Optional[float] = None

    try:
        proc = subprocess.Popen(
            ['udevadm', 'monitor', '--kernel', '--udev', '--subsystem-match=usb'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )

        while time.monotonic() - start_ts < duration:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue

            ts = time.monotonic() - start_ts
            evt = parse_udevadm_line(line, ts)
            if not evt:
                continue

            events.append(evt)
            elapsed = f"{ts:7.2f}s"

            if evt.action == 'connect':
                last_connect_ts = ts
                connect_times.append(ts)
                print(f"  {elapsed}  ▶  {evt.label}")

                # Auto-action: tenta DFU na janela de boot
                if auto_action and len(connect_times) >= 2:
                    avg_window = sum(window_durations[-3:]) / max(len(window_durations[-3:]), 1)
                    safe_delay = avg_window * 0.3  # age nos primeiros 30% da janela
                    print(f"           ↳ [AUTO] Janela ~{avg_window:.1f}s, agindo em {safe_delay:.2f}s...")
                    time.sleep(safe_delay)
                    try:
                        # Tenta DFU detach
                        subprocess.run(
                            ['dfu-util', '--device', '22d9:', '--detach'],
                            timeout=2, capture_output=True
                        )
                        print(f"           ↳ [AUTO] DFU detach enviado")
                    except:
                        pass

            elif evt.action == 'disconnect':
                disconnect_times.append(ts)
                if last_connect_ts is not None:
                    window = ts - last_connect_ts
                    window_durations.append(window)
                    print(f"  {elapsed}  ◀  {evt.label}  (ficou {window:.2f}s)")
                    last_connect_ts = None
                else:
                    print(f"  {elapsed}  ◀  {evt.label}")

    except KeyboardInterrupt:
        print("\n  [*] Interrompido pelo usuário")
    finally:
        try: proc.terminate()
        except: pass

    # ── Relatório de timing ────────────────────────────────────────────────
    print()
    print("═" * 55)
    print("  RELATÓRIO DE TIMING")
    print("═" * 55)

    total_cycles = min(len(connect_times), len(disconnect_times))
    print(f"  Ciclos completos detectados: {total_cycles}")

    if window_durations:
        avg_up = sum(window_durations) / len(window_durations)
        min_up = min(window_durations)
        max_up = max(window_durations)
        print(f"  Janela de disponibilidade:")
        print(f"    média:  {avg_up:.2f}s")
        print(f"    mínimo: {min_up:.2f}s")
        print(f"    máximo: {max_up:.2f}s")

        if len(disconnect_times) > 1 and len(connect_times) > 1:
            down_times = [
                connect_times[i+1] - disconnect_times[i]
                for i in range(min(len(connect_times)-1, len(disconnect_times)))
            ]
            if down_times:
                avg_down = sum(down_times) / len(down_times)
                print(f"  Tempo de reset (down):")
                print(f"    média:  {avg_down:.2f}s")

        print()
        print("  ESTRATÉGIA RECOMENDADA:")
        if avg_up > 2.0:
            print(f"    ✓ Janela larga ({avg_up:.1f}s) — dá pra tentar HID commands")
            print(f"    → Rode: mobius-fw-dump (tem tempo suficiente)")
        elif avg_up > 0.5:
            print(f"    ⚠ Janela curta ({avg_up:.1f}s) — DFU é mais rápido")
            print(f"    → Rode: dfu-util --device 22d9: --detach")
            print(f"    → Depois:  dfu-util --device 22d9: --download firmware.bin")
        else:
            print(f"    ✗ Janela muito curta ({avg_up:.2f}s) — firmware não está respondendo")
            print(f"    → Necessário acesso físico ao JTAG/SWD")
            print(f"    → Procure test points no PCB para SWD (SWDIO, SWDCLK, GND)")

        # PID detectado indica fase
        pids_seen = set(e.pid for e in events if e.action == 'connect')
        print()
        print("  PIDs detectados durante ciclo:")
        pid_map = {
            '0001': 'Modo normal (aplicação)',
            '0002': 'Bootloader/DFU mode',
            '0003': 'DFU detached',
        }
        for pid in pids_seen:
            label = pid_map.get(pid, 'Desconhecido')
            print(f"    0x{pid} → {label}")

        if '0002' in pids_seen:
            print()
            print("  ★ BOOTLOADER DETECTADO! Device entra em DFU mode.")
            print("    Isso é a melhor notícia possível — flash direto é viável.")
            print("    Janela DFU: ~{:.1f}s".format(avg_up))

    # Salva timeline
    if output:
        timeline = {
            "total_cycles": total_cycles,
            "avg_window_seconds": avg_up if window_durations else None,
            "events": [
                {"ts": e.ts, "action": e.action, "pid": e.pid,
                 "product": e.product}
                for e in events
            ]
        }
        output.write_text(json.dumps(timeline, indent=2))
        print(f"\n  [*] Timeline salva: {output}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Mobius Reset Loop Monitor')
    parser.add_argument('--duration', '-d', type=float, default=120.0,
                        help='Duração do monitoramento em segundos (default: 120)')
    parser.add_argument('--output', '-o', type=Path, default=None,
                        help='Salva timeline JSON (ex: timeline.json)')
    parser.add_argument('--auto', '-a', action='store_true',
                        help='Tenta DFU detach automaticamente na janela de boot')
    args = parser.parse_args()

    monitor_reset_loop(
        duration=args.duration,
        output=args.output,
        auto_action=args.auto,
    )


if __name__ == '__main__':
    main()
