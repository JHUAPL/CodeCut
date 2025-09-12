# @category Diagnostics
# @menupath Diagnostics.Test askYesNo
# @runtime PyGhidra

def main():
    try:
        # Ghidra injects askYesNo into the script's globals
        result = askYesNo("askYesNo Test", "Does askYesNo() work in this environment?")
        println(f"[test] askYesNo returned: {result!r}")
    except Exception as e:
        println(f"[test] askYesNo failed: {e}")

if __name__ == "__main__":
    main()
