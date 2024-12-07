import subprocess
import os
import time
import signal
import sys

# Global list to keep track of subprocesses
processes = []

def start_pipeline():
    """Start the Pipeline."""
    pipeline_path = os.path.join(os.getcwd(), "Pipeline", "Pipeline.py")
    if not os.path.exists(pipeline_path):
        raise FileNotFoundError(f"Pipeline.py not found at {pipeline_path}")
    print("Starting Pipeline...")
    process = subprocess.Popen(["python", pipeline_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(process)

def start_gui_backend():
    """Start the GUI Backend."""
    gui_backend_path = os.path.join(os.getcwd(), "Frontend", "GUI_Backend", "main.py")
    if not os.path.exists(gui_backend_path):
        raise FileNotFoundError(f"main.py not found at {gui_backend_path}")
    print("Starting GUI Backend...")
    process = subprocess.Popen(["python", gui_backend_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(process)

def start_react():
    """Start the React Frontend."""
    react_path = os.path.join(os.getcwd(), "Frontend", "GUI")
    package_json_path = os.path.join(react_path, "package.json")
    if not os.path.exists(package_json_path):
        raise FileNotFoundError(f"package.json not found at {react_path}. Ensure this is the React project's root.")
    print("Starting React Frontend...")
    process = subprocess.Popen(["npm", "run", "start"], cwd=react_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    processes.append(process)

def terminate_processes():
    """Terminate all subprocesses."""
    print("\nStopping all components...")
    for process in processes:
        try:
            process.terminate()  # Send SIGTERM to the process
            process.wait()  # Wait for the process to terminate
            print(f"Terminated process with PID: {process.pid}")
        except Exception as e:
            print(f"Error terminating process with PID {process.pid}: {e}")
    print("All components stopped.")

def signal_handler(sig, frame):
    """Handle Ctrl+C to gracefully stop all processes."""
    terminate_processes()
    sys.exit(0)

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    try:
        print("Initializing NeuraWall components...")
        start_pipeline()
        time.sleep(2)  # Allow time for initialization
        start_gui_backend()
        time.sleep(2)  # Allow time for initialization
        start_react()
        print("All components started successfully!")
        print("Press Ctrl+C to stop all components.")
        
        # Keep the script running to maintain processes
        while True:
            time.sleep(1)
    except FileNotFoundError as fnfe:
        print(f"File error: {fnfe}")
    except Exception as e:
        print(f"Error starting components: {e}")
        terminate_processes()

if __name__ == "__main__":
    main()
