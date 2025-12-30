# Contributing to Baluarte

Thank you for your interest in contributing to Baluarte! We welcome all contributions, including bug fixes, new features, and improvements to documentation.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/your-username/baluarte.git
    cd baluarte
    ```
3.  **Install dependencies**:
    ```bash
    composer install
    ```
4.  **Create a new branch** for your changes:
    ```bash
    git checkout -b feature/your-feature-name
    ```

## Coding Standards

-   Follow [PSR-12](https://www.php-fig.org/psr/psr-12/) coding standards.
-   Add inline PHPDoc for all new classes and methods.
-   Ensure your code is well-commented where necessary.

## Testing

Baluarte uses PHPUnit for testing. Before submitting a pull request, please ensure all tests pass:

```bash
vendor/bin/phpunit
```

If you add a new feature, please include corresponding tests in the `tests/` directory.

## Submitting a Pull Request

1.  **Commit your changes** with a descriptive commit message:
    ```bash
    git commit -m "Add feature: your feature description"
    ```
2.  **Push your branch** to your fork:
    ```bash
    git push origin feature/your-feature-name
    ```
3.  **Open a Pull Request** on the main Baluarte repository. Provide a clear description of your changes and reference any related issues.

## Reporting Issues

If you find a bug or have a suggestion for improvement, please open an issue on GitHub. Provide as much detail as possible, including steps to reproduce the issue and your environment details.

## License

By contributing to Baluarte, you agree that your contributions will be licensed under the project's [GPL-3.0-or-later](LICENSE) license.
