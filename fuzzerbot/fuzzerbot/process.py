import os
import re
import subprocess

CRASH_RUNNER = 'just crash'

FILTERS = []

def process_crash_report(filename):
    try:
        output = run_crash(filename)
        if output:
            panic_log = extract_panic(output)

            if panic_log:
                if is_filtered(panic_log):
                    return True, format_filtered_message(filename, "\n".join(panic_log))
                return False, format_message(filename, "\n".join(panic_log))
            else:
                return True, format_message(filename, "No panic log found in the log.")
        else:
            return True, format_message(filename, f"{CRASH_RUNNER} produced no output.")
    except Exception as e:
        print(f"Error processing crash report: {e}")
        return None


def is_filtered(report):
    for line in report:
        if any(filter_ in line for filter_ in FILTERS):
            return True

    return False


def run_crash(file_path):
    CRASH_SCRIPT_DIR = os.getenv('CRASH_SCRIPT_DIR')
    try:
        p = CRASH_RUNNER.split()
        p.append(file_path)
        result = subprocess.run(p, capture_output=True, text=True, cwd=CRASH_SCRIPT_DIR)
        return result.stdout + result.stderr
    except Exception as e:
        print(f"Error running script: {e}")
        return None


def extract_panic(log):
    lines = log.splitlines()

    stack_trace_start = None
    stack_trace_end = None
    for i, line in enumerate(lines):
        if re.match(r"^thread 'main' panicked\s*", line):
            stack_trace_start = i
        if re.match(r"^stack backtrace\s*", line):
            stack_trace_end = i

        if stack_trace_start and stack_trace_end:
            break

    if stack_trace_start and stack_trace_start:
        return lines[stack_trace_start:stack_trace_end]
    else:
        return None  # If no stack trace is found


def format_message(fn, message):
    filename = f"Crash report: {fn}"
    report = f"```{message}```"
    return f"{filename}\n{report}"

#

def format_filtered_message(fn, message):
    filename = f"Crash report: {fn}"
    report = f"```{message}```"
    return f"-----------FILTERED----------\n{filename}\n{report}\n-------------------"

#
