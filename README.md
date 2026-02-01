# HeXor

A collection of two minimal, header-only C++ libraries for heavyweight pointer encryption and string obfuscation.

---

## Overview

This repository contains the following utilities:

- **PointerCrypt.h** – A simple, header-only solution for strong encryption and decryption (“heavyweight”) of pointers at runtime or compile time.
- **HeXor.h** – A simple, header-only solution for strong (“heavyweight”) compile-time and runtime string obfuscation and decoding.

Both headers are lightweight, dependency-free, and extremely easy to use in your C++ projects.

---

## Features

### PointerCrypt.h

- Encrypts/decrypts pointers to prevent easy static/dynamic analysis.
- Works at compile-time or runtime.
- No external dependencies.
- Very simple API.

### HeXor.h

- Obfuscates string literals using strong algorithms (XOR- or custom-based).
- Compile-time encoding prevents string exposure in binaries.
- Runtime decoding on demand.
- Simple integration – just include and use.

---

## Getting Started

### Installation

Just copy the headers you need into your project:

```
your_project/
  ├─ include/
  │    ├─ HeXor.h
  │    └─ PointerCrypt.h
  └─ ...
```

or use them directly from this repository via `#include`.

---

## Usage

### **PointerCrypt.h** Example

```cpp
#include "PointerCrypt.h"

class HelloWorld
{
  HelloWorld() = default;
  ~HelloWorld() = default;
  
 public:
    void PrintMe()
    {
      std::cout << "Called from class" << std::endl;
    }
};

int main() {
  std::unique_ptr<HiddenPtr<HelloWorld>> HiddenPointer = std::make_unique<HiddenPtr<HelloWorld>>();
  HiddenPointer->get()->PrintMe();
  return 0;
}
```

---

### **HeXor.h** Example

```cpp
#include "HeXor.h"

int main()
{
  // Compile-time obfuscation
  constexpr auto obf = HeXor("Hidden String");
  
  std::cout << obf << std::endl;
  return 0;
}
```

---

## Why "Heavyweight"?

Both headers use stronger obfuscation/encryption mechanisms than trivial XOR or pointer mangling, for robust protection against reverse engineering.

---

## License

This project is licensed under the MIT License – see the [LICENSE](./LICENSE) file for details.

---

## Author

[VMWRITE](https://github.com/VMWRITE)

---

## Notes

- Tested with modern C++ compiler (C++23).
- No external dependencies.
- For any questions or suggestions, open an [issue](https://github.com/VMWRITE/HeXor/issues).

**Star the project if you find it useful!**
