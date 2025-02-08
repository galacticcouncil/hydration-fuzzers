import os
import re
import subprocess

CRASH_RUNNER = 'just crash'
CRASH_SCRIPT_DIR = os.getenv('CRASH_SCRIPT_DIR') or "."


def process_crash_report(filename):
    try:
        output = run_crash(filename)
        if output:
            last_lines = extract_last_lines_before_stack_trace(output)
            if last_lines:
                return format_message(filename, "\n".join(last_lines))
            else:
                return "No stack trace found in the log."
        else:
            return "No output from the custom script."
    except Exception as e:
        print(f"Error processing crash report: {e}")
        return None


def run_crash(file_path):
    try:
        p = CRASH_RUNNER.split()
        p.append(file_path)
        result = subprocess.run(p, capture_output=True, text=True, cwd=CRASH_SCRIPT_DIR)
        return result.stdout + result.stderr
    except Exception as e:
        print(f"Error running script: {e}")
        return None


def extract_last_lines_before_stack_trace(log, nbr=10):
    lines = log.splitlines()

    stack_trace_start = None
    for i, line in enumerate(lines):
        if re.match(r"^stack backtrace\s*", line):
            stack_trace_start = i
            break

    if stack_trace_start is not None:
        start_line = max(0, stack_trace_start - nbr)
        return lines[start_line:stack_trace_start]
    else:
        return None  # If no stack trace is found


def format_message(fn, message):
    filename = f"Crash report: {fn}"
    report = f"```{message}```"
    return f"{filename}\n{report}"

#
