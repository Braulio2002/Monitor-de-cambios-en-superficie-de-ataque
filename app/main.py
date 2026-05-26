from app.presentation.cli import AttackSurfaceMonitorCLI


def main() -> None:
    """
    Punto de entrada de la aplicación.
    Inicializa y ejecuta la interfaz de línea de comandos.
    """
    cli = AttackSurfaceMonitorCLI()
    cli.run()


if __name__ == "__main__":
    main()
