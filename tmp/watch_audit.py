#!/usr/bin/env python3
"""Watch and colorize MCP Firewall audit log in real-time."""
import sys
import json
import subprocess

def watch_audit_log(log_file="mcpfw-audit.log"):
    """Tail the audit log and print colorized output."""
    try:
        # Start tail -f process
        process = subprocess.Popen(
            ["tail", "-f", log_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print(f"Watching {log_file}... (Press Ctrl+C to stop)\n")
        
        for line in process.stdout:
            try:
                e = json.loads(line)
                v = e.get('verdict', '').upper()
                
                # Color codes
                if v == 'ALLOW':
                    color = '\033[32m'  # Green
                elif v == 'BLOCK':
                    color = '\033[31m'  # Red
                else:
                    color = '\033[33m'  # Yellow
                
                reset = '\033[0m'
                
                tool_name = e.get('tool_name', '-')
                ruled_by = e.get('ruled_by', '')
                reason = e.get('reason', '')
                
                print(f"{color}[{v}]{reset}  tool={tool_name:<22} ruled_by={ruled_by:<10} {reason}")
                
            except json.JSONDecodeError:
                # Not JSON, print as-is
                print(line, end='')
            except Exception as ex:
                print(f"Error parsing line: {ex}")
                print(line, end='')
                
    except KeyboardInterrupt:
        print("\n\nStopped watching audit log.")
        process.terminate()
    except FileNotFoundError:
        print(f"Error: {log_file} not found. Make sure the firewall is running.")
        sys.exit(1)

if __name__ == "__main__":
    log_file = sys.argv[1] if len(sys.argv) > 1 else "mcpfw-audit.log"
    watch_audit_log(log_file)
