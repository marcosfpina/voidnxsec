{
  description = "Audeze Mobius Firmware Reverse Engineering Kit";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ { flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" ];

      perSystem = { config, pkgs, system, ... }:
        let
          # ──────────────────────────────────────────────
          # Audeze Mobius USB IDs (confirmados via lsusb)
          # Ajuste se o teu unit responder diferente
          # ──────────────────────────────────────────────
          audeze = {
            vid = "0x22d9"; # Audeze LLC — confirmar com: lsusb | grep -i audeze
            pid = "0x0001"; # Mobius (bootloader: 0x0002, DFU: 0x0003)
          };

          # Python com todas as libs de RE/USB que precisamos
          pythonEnv = pkgs.python313.withPackages (ps: with ps; [
            # USB / HID
            pyusb
            hid

            # Parsing binário estruturado — o construct é rei aqui
            construct

            # Disassembler embeddado
            capstone

            # Análise de entropia (detecta seções comprimidas/encriptadas)
            matplotlib
            numpy

            # Scripting USB capture
            scapy

            # Utils gerais
            click
            rich
            hexdump
          ]);

          # Script auxiliar: detecta o Mobius e imprime estado USB atual
          usbProbe = pkgs.writeShellScriptBin "mobius-probe" ''
            #!/usr/bin/env bash
            set -euo pipefail

            echo "=== Audeze Mobius USB Probe ==="
            echo ""

            # Detecta device
            DEVICE=$(lsusb | grep -i "audeze\|22d9\|mobius" || true)
            if [ -z "$DEVICE" ]; then
              echo "[WARN] Audeze Mobius não encontrado no bus USB."
              echo "       Verifique: cabo, porta, modo (normal vs DFU)"
              echo ""
              echo "Todos os devices USB:"
              lsusb
              exit 1
            fi

            echo "[OK] Device encontrado:"
            echo "     $DEVICE"
            echo ""

            # Extrai BUS:DEV
            BUS=$(echo "$DEVICE" | awk '{print $2}')
            DEV=$(echo "$DEVICE" | awk '{print $4}' | tr -d ':')

            echo "=== Descriptor USB detalhado ==="
            sudo lsusb -v -s "$BUS:$DEV" 2>/dev/null || \
              echo "[!] Rode como root para descriptor completo"

            echo ""
            echo "=== Interfaces de áudio ==="
            sudo lsusb -v -s "$BUS:$DEV" 2>/dev/null | \
              grep -A2 "bInterfaceClass\|bAlternateSetting\|wMaxPacketSize" || true

            echo ""
            echo "=== Kernel driver binding ==="
            SYSFS=$(find /sys/bus/usb/devices -name "idVendor" \
              -exec grep -l "22d9" {} \; 2>/dev/null | head -1 | xargs dirname || true)
            if [ -n "$SYSFS" ]; then
              echo "sysfs: $SYSFS"
              ls "$SYSFS/" 2>/dev/null || true
            fi
          '';

          # Script: captura tráfego USB do Mobius via usbmon
          usbCapture = pkgs.writeShellScriptBin "mobius-capture" ''
            #!/usr/bin/env bash
            set -euo pipefail

            OUTFILE="''${1:-mobius-capture-$(date +%Y%m%d_%H%M%S).pcapng}"

            echo "=== Audeze Mobius USB Traffic Capture ==="
            echo "Output: $OUTFILE"
            echo ""

            # Precisamos do módulo usbmon
            if ! lsmod | grep -q usbmon; then
              echo "[*] Carregando módulo usbmon..."
              sudo modprobe usbmon
            fi

            # Descobre qual bus o Mobius está
            DEVICE_LINE=$(lsusb | grep -i "audeze\|22d9" | head -1)
            if [ -z "$DEVICE_LINE" ]; then
              echo "[!] Mobius não encontrado. Conecte o device primeiro."
              exit 1
            fi

            BUS=$(echo "$DEVICE_LINE" | awk '{print $2}' | sed 's/^0*//')
            echo "[*] Mobius no Bus $BUS — capturando em usbmon$BUS"
            echo "[*] Ctrl+C para parar"
            echo ""

            # Tshark é mais útil que tcpdump para USB
            sudo tshark \
              -i "usbmon$BUS" \
              -w "$OUTFILE" \
              -f "usb" \
              2>/dev/null &
            TSHARK_PID=$!

            echo "[*] Captura iniciada (PID: $TSHARK_PID)"
            echo "    Abra o DMU ou execute operações no headset agora."
            echo "    Para analisar depois: wireshark $OUTFILE"
            echo ""
            echo "    Ou em tempo real:"
            echo "    sudo tshark -i usbmon$BUS -Y 'usb.transfer_type == 0x01' -T fields \\"
            echo "      -e usb.endpoint_address -e usb.data_len -e usb.capdata"

            wait $TSHARK_PID
          '';

          # Script: dump do firmware atual via DFU ou HID vendor command
          fwDump = pkgs.writeShellScriptBin "mobius-fw-dump" ''
            #!/usr/bin/env bash
            set -euo pipefail

            OUTDIR="''${1:-./fw-dump-$(date +%Y%m%d_%H%M%S)}"
            mkdir -p "$OUTDIR"

            echo "=== Audeze Mobius Firmware Dump ==="
            echo "Output: $OUTDIR/"
            echo ""

            # Tenta DFU upload primeiro (se o device está em modo DFU)
            if lsusb | grep -qi "dfu\|0483:df11\|22d9:0002"; then
              echo "[*] Device em modo DFU detectado — tentando upload via dfu-util..."
              dfu-util \
                --upload "$OUTDIR/firmware-dfu-dump.bin" \
                --alt 0 \
                --verbose \
                || echo "[WARN] DFU upload falhou — device pode não suportar DFU_UPLOAD"
            fi

            # Tenta via HID — Vendor-specific read command
            echo "[*] Tentando dump via HID vendor commands..."
            ${pythonEnv}/bin/python3 ${./scripts/hid-fw-dump.py} \
              --output "$OUTDIR/firmware-hid-dump.bin" \
              || echo "[WARN] HID dump falhou — analise o capture USB do DMU primeiro"

            echo ""
            echo "=== Analisando binários encontrados ==="
            for f in "$OUTDIR"/*.bin; do
              if [ -f "$f" ]; then
                echo ""
                echo "--- $f ---"
                echo "Size: $(wc -c < "$f") bytes"
                echo "Entropy (primeiros 256 bytes):"
                head -c 256 "$f" | od -An -tx1 | \
                  awk '{for(i=1;i<=NF;i++) printf "%d ", strtonum("0x"$i); print ""}' | \
                  tr ' ' '\n' | sort | uniq -c | \
                  awk '{print $2": "$1}' | sort -n | tail -5
                echo "Magic bytes:"
                xxd "$f" | head -4
              fi
            done

            echo ""
            echo "[OK] Done. Próximo passo: mobius-analyze $OUTDIR/"
          '';

          # Script: análise estática do firmware
          fwAnalyze = pkgs.writeShellScriptBin "mobius-analyze" ''
            #!/usr/bin/env bash
            set -euo pipefail

            TARGET="''${1:-.}"
            echo "=== Audeze Mobius Firmware Analysis ==="
            echo "Target: $TARGET"
            echo ""

            for fw in "$TARGET"/*.bin "$TARGET"/*.hex "$TARGET"/*.dfu 2>/dev/null; do
              [ -f "$fw" ] || continue
              echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
              echo "Arquivo: $fw"
              echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

              # binwalk: identifica estruturas, compressão, filesystems
              echo ""
              echo "[binwalk] Identificando estruturas..."
              binwalk --term "$fw" 2>/dev/null || binwalk "$fw"

              # Entropia — seção encriptada tem entropia ~1.0
              echo ""
              echo "[binwalk] Mapa de entropia..."
              binwalk --entropy --save --term "$fw" 2>/dev/null || true

              # strings: extrai strings legíveis (versão, datas, etc)
              echo ""
              echo "[strings] Strings interessantes (≥6 chars)..."
              strings -n 6 "$fw" | grep -iE \
                "version|firmware|fw|v[0-9]+\.[0-9]|audeze|mobius|dsp|boot|flash|error|fail|ok|usb|hid|audio|eq|dfu|update" \
                | head -40

              # file: identifica formato
              echo ""
              echo "[file] Tipo do binário:"
              file "$fw"

              echo ""
            done

            echo ""
            echo "[*] Para análise profunda: mobius-ghidra"
            echo "[*] Para RE interativa:    r2 -A <firmware.bin>"
          '';

          # Script: flash seguro com backup automático
          fwFlash = pkgs.writeShellScriptBin "mobius-flash" ''
            #!/usr/bin/env bash
            set -euo pipefail

            FIRMWARE="$1"
            BACKUP_DIR="./fw-backup-$(date +%Y%m%d_%H%M%S)"

            if [ -z "$FIRMWARE" ]; then
              echo "Usage: mobius-flash <firmware.bin>"
              echo ""
              echo "Esse script flash via DFU com backup automático."
              echo "Coloque o Mobius em modo DFU antes:"
              echo "  - Segure o botão power por 10s (varia por versão)"
              echo "  - Ou: dfu-util --device 22d9: --detach"
              exit 1
            fi

            if [ ! -f "$FIRMWARE" ]; then
              echo "[!] Firmware não encontrado: $FIRMWARE"
              exit 1
            fi

            echo "=== Audeze Mobius Safe Firmware Flash ==="
            echo "Firmware: $FIRMWARE ($(wc -c < "$FIRMWARE") bytes)"
            echo ""

            # Backup primeiro, sempre
            mkdir -p "$BACKUP_DIR"
            echo "[*] Tentando backup antes do flash..."
            dfu-util --upload "$BACKUP_DIR/pre-flash-backup.bin" --alt 0 2>/dev/null \
              && echo "[OK] Backup salvo em $BACKUP_DIR/pre-flash-backup.bin" \
              || echo "[WARN] Backup não disponível (DFU_UPLOAD não suportado)"

            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "ATENÇÃO: Flash direto pode brickar o device"
            echo "Firmware: $FIRMWARE"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            read -rp "Confirmar flash? [sim/NÃO] " CONFIRM
            if [ "$CONFIRM" != "sim" ]; then
              echo "Abortado."
              exit 0
            fi

            echo ""
            echo "[*] Iniciando flash..."
            dfu-util \
              --device 22d9: \
              --alt 0 \
              --download "$FIRMWARE" \
              --reset \
              --verbose

            echo ""
            echo "[OK] Flash completo. Reconectando..."
            sleep 3
            mobius-probe || true
          '';

          # Script: abre Ghidra com projeto pré-configurado pro Mobius
          ghidraLaunch = pkgs.writeShellScriptBin "mobius-ghidra" ''
            #!/usr/bin/env bash
            set -euo pipefail

            FW="''${1:-}"
            PROJ_DIR="$HOME/.ghidra-mobius"
            mkdir -p "$PROJ_DIR"

            echo "=== Audeze Mobius Ghidra Analysis ==="
            if [ -n "$FW" ]; then
              echo "Firmware: $FW"
              # Importa headless primeiro para pre-análise
              echo "[*] Rodando análise headless (pode demorar alguns minutos)..."
              analyzeHeadless \
                "$PROJ_DIR" "MobiusRE" \
                -import "$FW" \
                -processor "ARM:LE:32:Cortex" \
                -cspec "default" \
                -scriptPath "${./ghidra}" \
                -postScript "MobiusAutoAnalysis.py" \
                2>/dev/null \
                && echo "[OK] Análise headless completa" \
                || echo "[WARN] Headless falhou — abrindo GUI diretamente"
            fi

            echo "[*] Abrindo Ghidra GUI..."
            ghidra &
            echo ""
            echo "No Ghidra:"
            echo "  1. File > Open Project > $PROJ_DIR/MobiusRE.gpr"
            echo "  2. Window > Script Manager > MobiusAutoAnalysis.py"
          '';

          # rizin wrapper com profile para ARM embedded
          r2Mobius = pkgs.writeShellScriptBin "r2-mobius" ''
            #!/usr/bin/env bash
            FW="''${1:-firmware.bin}"
            # ARM Cortex-M é o mais provável no Mobius
            # -b 16 para Thumb, -m 0x08000000 base de flash STM32
            rizin \
              -a arm \
              -b 16 \
              -m 0x08000000 \
              -A \
              "$FW"
          '';

        in {
          # ── Dev Shell ───────────────────────────────────────────────────────
          devShells.default = pkgs.mkShell {
            name = "audeze-mobius-re";

            packages = with pkgs; [
              # ── USB / Device access ──────────────────────────────────────
              libusb1
              usbutils        # lsusb, usb-devices
              dfu-util        # flash via DFU
              dfu-programmer  # AVR DFU (fallback)
              hidapi          # HID raw access
              wireshark       # análise de capture USB
              tshark          # wireshark CLI
              usbmuxd         # caso seja necessário

              # ── Análise binária ───────────────────────────────────────────
              binwalk         # identificação de estruturas em firmware
              ghidra          # RE pesada — o cavalo de batalha
              rizin           # r2 moderno, ótimo pra scripting
              radare2         # r2 clássico
              hexedit         # hex editor no terminal
              imhex           # hex editor com GUI — ótimo pra firmware
              bintools        # extração de strings

              # ── Toolchains (compilação/cross) ─────────────────────────────
              gcc-arm-embedded   # ARM Cortex-M toolchain
              pkgsCross.armhf-embedded.stdenv.cc  # ARM HF cross-compiler
              # avrdude          # se for AVR (menos provável no Mobius)

              # ── Debug / Flashing ──────────────────────────────────────────
              openocd          # on-chip debugging via JTAG/SWD
              stlink           # ST-Link programmer/debugger (STM32)
              pyocd            # PyOCD — alternativa ao openocd

              # ── Python environment ────────────────────────────────────────
              pythonEnv

              # ── Protocolo / Análise de sinal ──────────────────────────────
              sigrok-cli       # análise de protocolo (serial, I2C, SPI)
              pulseview        # GUI do sigrok

              # ── Utilitários ───────────────────────────────────────────────
              xxd
              file
              binutils
              elfutils         # readelf, objdump etc
              pkgs.patchelf

              # ── Scripts customizados ──────────────────────────────────────
              usbProbe
              usbCapture
              fwDump
              fwAnalyze
              fwFlash
              ghidraLaunch
              r2Mobius
            ];

            shellHook = ''
              echo ""
              echo "╔══════════════════════════════════════════════════════╗"
              echo "║    Audeze Mobius Firmware RE Kit — voidnxlabs        ║"
              echo "╚══════════════════════════════════════════════════════╝"
              echo ""
              echo "  Comandos disponíveis:"
              echo "    mobius-probe      — detecta e inspeciona o device USB"
              echo "    mobius-capture    — captura tráfego USB (requer root)"
              echo "    mobius-fw-dump    — tenta dump do firmware atual"
              echo "    mobius-analyze    — análise estática de binários"
              echo "    mobius-flash <fw> — flash seguro com backup automático"
              echo "    mobius-ghidra     — abre Ghidra com projeto configurado"
              echo "    r2-mobius <fw>    — rizin com profile ARM Cortex-M"
              echo ""
              echo "  Fluxo recomendado:"
              echo "    1. Coloca o Mobius — mobius-probe"
              echo "    2. Captura o DMU fazendo update — mobius-capture"
              echo "    3. Analisa o .bin original que você tem — mobius-analyze ./fw/"
              echo "    4. RE com ghidra ou r2 — mobius-ghidra firmware.bin"
              echo "    5. Patch + flash — mobius-flash firmware-patched.bin"
              echo ""
              echo "  udev rules: sudo cp udev/99-audeze.rules /etc/udev/rules.d/"
              echo "              sudo udevadm control --reload-rules"
              echo ""

              # Verifica se o device está conectado na entrada
              if lsusb 2>/dev/null | grep -qi "audeze\|22d9"; then
                echo "  [OK] Audeze Mobius detectado no bus USB!"
              else
                echo "  [--] Audeze Mobius não detectado (ok, conecte quando quiser)"
              fi
              echo ""
            '';

            # Necessário para USB sem root no shell
            LIBUSB_DEBUG = "0";
            # OpenOCD não reclama de permissões
            OPENOCD_SCRIPTS = "${pkgs.openocd}/share/openocd/scripts";
          };
        };
    };
}
