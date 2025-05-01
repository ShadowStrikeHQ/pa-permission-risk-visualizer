import argparse
import logging
import os
import sys
import stat
from typing import List, Dict, Tuple
from rich.console import Console
from rich.table import Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
OUTPUT_FORMATS = ["dot", "png"]  # Supported output formats for the graph
DEFAULT_OUTPUT_FILE = "permission_risk_graph.png"

class PermissionRiskVisualizer:
    """
    A tool for visualizing permission risks within a file system.
    """

    def __init__(self, root_path: str, output_file: str, output_format: str, console: Console):
        """
        Initializes the PermissionRiskVisualizer.

        Args:
            root_path: The root directory to analyze.
            output_file: The file to save the visualization to.
            output_format: The format of the output file (e.g., "dot", "png").
            console: Rich Console object for output.
        """
        self.root_path = root_path
        self.output_file = output_file
        self.output_format = output_format
        self.console = console
        self.permissions_data: Dict[str, Dict[str, str]] = {}

    def gather_permissions_data(self) -> None:
        """
        Gathers permission data for files and directories under the root path.
        """
        self.permissions_data = {}  # Reset data for each run

        for root, _, files in os.walk(self.root_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    stat_info = os.stat(filepath)
                    self.permissions_data[filepath] = {
                        "mode": stat.filemode(stat_info.st_mode),
                        "owner": str(stat_info.st_uid),  # Convert uid to string
                        "group": str(stat_info.st_gid),  # Convert gid to string
                    }
                except OSError as e:
                    logging.error(f"Error gathering permissions for {filepath}: {e}")

    def analyze_risks(self) -> List[Tuple[str, str]]:
        """
        Analyzes gathered permission data for potential risks (e.g., overly permissive files).

        Returns:
            A list of tuples, where each tuple contains the filepath and a description of the risk.
        """
        risks: List[Tuple[str, str]] = []

        for filepath, data in self.permissions_data.items():
            mode = data["mode"]

            # Check for overly permissive files (e.g., world-writable files)
            if mode.startswith("-") and mode.endswith("rwxrwxrwx"):
                risks.append((filepath, "World-writable file detected."))
            elif mode.startswith("-") and mode.endswith("rw-rw-rw-"):
                risks.append((filepath, "World-readable and writeable file detected."))

            # Add more sophisticated risk analysis logic here as needed
            # (e.g., check for setuid/setgid bits, excessive permissions for specific users)

        return risks

    def generate_graph(self, risks: List[Tuple[str, str]]) -> str:
        """
        Generates a graph representation of the permission risks in DOT format.

        Args:
            risks: A list of tuples, where each tuple contains the filepath and a description of the risk.

        Returns:
            A string representing the graph in DOT format.
        """

        dot_graph = "digraph PermissionRisks {\n"
        dot_graph += "  node [shape=box];\n"  # Style for nodes

        for filepath, risk_description in risks:
            # Sanitize filepath for DOT format (replace special characters)
            node_name = filepath.replace("/", "_").replace(".", "_").replace("\\", "_")  # Handling Windows paths too
            dot_graph += f'  "{node_name}" [label="{filepath}\\nRisk: {risk_description}"];\n'

        # Add edges if needed (e.g., to show ownership relationships) - Not implemented in this basic example
        # For example, if user A owns file B, you could add an edge:
        # dot_graph += f'  "{user_A_node}" -> "{file_B_node}";\n'

        dot_graph += "}\n"
        return dot_graph

    def output_graph(self, dot_graph: str) -> None:
        """
        Outputs the graph to the specified file, converting to PNG if necessary.
        Requires graphviz to be installed to convert to PNG.

        Args:
            dot_graph: The graph in DOT format.
        """
        try:
            with open("temp_graph.dot", "w") as f:
                f.write(dot_graph)

            if self.output_format == "png":
                # Convert DOT to PNG using graphviz
                try:
                    import subprocess
                    subprocess.run(
                        ["dot", "-Tpng", "temp_graph.dot", "-o", self.output_file],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    logging.info(f"Graph saved to {self.output_file} (PNG format).")
                except FileNotFoundError:
                    self.console.print_exception()
                    logging.error("Graphviz 'dot' command not found. Please install graphviz to generate PNG output.")
                except subprocess.CalledProcessError as e:
                      logging.error(f"Error converting DOT to PNG: {e.stderr}")
                      self.console.print_exception()

            elif self.output_format == "dot":
                # Save as DOT format directly
                os.rename("temp_graph.dot", self.output_file) #Rename to proper output file name
                logging.info(f"Graph saved to {self.output_file} (DOT format).")
            else:
                logging.error(f"Invalid output format: {self.output_format}")

        except OSError as e:
            logging.error(f"Error writing graph to file: {e}")
        finally:
            if os.path.exists("temp_graph.dot"): #Clean up the temp file even if it fails.
                os.remove("temp_graph.dot")

    def display_risks_table(self, risks: List[Tuple[str, str]]) -> None:
        """
        Displays the identified permission risks in a table format.
        Args:
            risks:  A list of tuples, where each tuple contains the filepath and a description of the risk.
        """
        if not risks:
            self.console.print("[bold green]No permission risks found.[/]")
            return

        table = Table(title="Permission Risk Assessment")
        table.add_column("File Path", justify="left", style="cyan", no_wrap=True)
        table.add_column("Risk Description", justify="left", style="red")

        for filepath, risk_description in risks:
            table.add_row(filepath, risk_description)

        self.console.print(table)

    def run(self) -> None:
        """
        Runs the permission risk visualization process.
        """
        try:
            self.gather_permissions_data()
            risks = self.analyze_risks()
            self.display_risks_table(risks)
            dot_graph = self.generate_graph(risks)
            self.output_graph(dot_graph)


        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            self.console.print_exception()


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        An argparse.ArgumentParser object.
    """
    parser = argparse.ArgumentParser(
        description="Generates a visual representation of permission risks, highlighting over-permissioned users and potential privilege escalation paths.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "root_path",
        help="The root directory to analyze.",
        type=str,
        metavar="ROOT_PATH",
    )

    parser.add_argument(
        "-o",
        "--output-file",
        help=f"The file to save the visualization to (default: {DEFAULT_OUTPUT_FILE}).",
        type=str,
        default=DEFAULT_OUTPUT_FILE,
    )

    parser.add_argument(
        "-f",
        "--output-format",
        help=f"The format of the output file (default: png, options: {', '.join(OUTPUT_FORMATS)}).",
        type=str,
        default="png",
        choices=OUTPUT_FORMATS,
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose logging (debug level).",
        action="store_true",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """
    Validates the command-line arguments.

    Args:
        args: The argparse.Namespace object containing the parsed arguments.

    Raises:
        ValueError: If any of the arguments are invalid.
    """
    if not os.path.isdir(args.root_path):
        raise ValueError(f"Root path '{args.root_path}' is not a valid directory.")

    if not args.output_file:
        raise ValueError("Output file cannot be empty.")

    if args.output_format not in OUTPUT_FORMATS:
        raise ValueError(f"Invalid output format: {args.output_format}. Supported formats are: {', '.join(OUTPUT_FORMATS)}")

def main() -> None:
    """
    Main function to execute the permission risk visualizer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    try:
        validate_args(args)
    except ValueError as e:
        logging.error(f"Argument validation error: {e}")
        parser.print_help()
        sys.exit(1)

    console = Console()
    visualizer = PermissionRiskVisualizer(args.root_path, args.output_file, args.output_format, console)

    try:
        visualizer.run()
    except Exception as e:
        logging.error(f"An error occurred during execution: {e}")
        console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    #Example Usage
    #Example: python main.py /path/to/analyze -o output.png -f png
    #Example: python main.py /path/to/analyze -f dot > output.dot
    #Example: python main.py /path/to/analyze -v
    main()