import sys
import argparse
from utils import is_admin
import cli


def main() -> None:
    """
    Main entry point for the Network Mapper application.
    Checks for administrator privileges and launches either the GUI or CLI mode.
    :return: None
    """
    # check administrator/root privileges
    if not is_admin():
        print("Error: This script requires administrator/root privileges to run.")
        sys.exit(1)

    # argument parsing for GUI check before loading full CLI or GUI modules
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-g", "--gui", action="store_true")
    args, unknown = parser.parse_known_args()

    if args.gui:
        try:
            import gui
            print("Starting GUI...")
            gui_app = gui.NetworkMapperGUI()
            gui_app.mainloop()
        except ImportError as e:
            print(f"Error: GUI components (ttkbootstrap) not found or tkinter is missing. {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Failed to start GUI: {e}")
            sys.exit(1)
    else:
        # pass control to the CLI module
        cli.main()


if __name__ == "__main__":
    main()
