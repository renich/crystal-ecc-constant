# crystal-ecc-constant

A constant-time Elliptic Curve Cryptography wrapper for LibSodium in Crystal.

## Features
- Class-based reference semantics to completely eradicate double-free and use-after-free vulnerabilities.
- Constant-time operations preventing side-channel timing attacks.
- Hardened memory isolation.

## Usage
Add this to your application's `shard.yml`:
```yaml
dependencies:
  crystal-ecc-constant:
    github: renich/crystal-ecc-constant
```

## Documentation
Full architectural and API documentation is available in the `docs/` directory. Use `make docs` to generate the HTML.

## Credits
- **Co-developed-by**: Gemini AI <renich+gemini@woralelandia.com>
- **Signed-off-by**: Rénich Bon Ćirić <renich@woralelandia.com>

## Code of Honor
This project strictly adheres to the [Code of Honor](docs/technical/CODE_OF_HONOR.rst) drafted by Rénich Bon Ćirić.
