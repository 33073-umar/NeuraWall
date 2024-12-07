import shutil
import subprocess
import sys
import os
import yaml

def install_python_dependencies(dependencies):
    """Install Python dependencies."""
    for package in dependencies:
        print(f"Installing Python package: {package}")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", package], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package}: {e}")

def install_node_dependencies(dependencies, working_dir):
    """Install Node.js dependencies in the specified directory."""
    npm_path = shutil.which("npm")  # Get the full path to npm
    if not npm_path:
        print("npm not found. Ensure Node.js is installed and npm is in the PATH.")
        sys.exit(1)

    print(f"Using npm at: {npm_path}")
    try:
        # Ensure the working directory exists
        if not os.path.exists(working_dir):
            print(f"Node.js working directory {working_dir} does not exist.")
            sys.exit(1)

        # Ensure a package.json exists in the target directory
        if not os.path.exists(os.path.join(working_dir, "package.json")):
            print("No package.json found. Initializing...")
            subprocess.run([npm_path, "init", "-y"], cwd=working_dir, check=True)

        # Install each dependency
        for package in dependencies:
            print(f"Installing Node.js package: {package}")
            subprocess.run([npm_path, "install", package], cwd=working_dir, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to install Node.js dependencies: {e}")

def main():
    with open("dependencies.yaml", "r") as file:
        deps = yaml.safe_load(file)



    # Install Node.js dependencies
    node_dependencies = deps.get("node", [])
    if node_dependencies:
        # Specify the directory where the package.json is located
        node_working_dir = os.path.join(os.getcwd(), "Frontend", "GUI")
        print(f"Installing Node.js dependencies in: {node_working_dir}")
        install_node_dependencies(node_dependencies, node_working_dir)

if __name__ == "__main__":
    main()
