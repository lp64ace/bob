<div align="center">
	<p align="center">
		<img src="logo.png" alt="Bob" width="128"/>
	</p>
</div>

# Portable Executable Loader

The operation is usually refered to as DLL Injection although the technique is manual mapping of the DLL to a remote process.

# How it Works

The DLL main is triggered by a remote thread created on the target application after mapping all the sections into memory and triggering necessary procedures for Thread Local storage and initializers.

# Build

Download the repository through github or git!

```sh
git clone https://github.com/lp64ace/bob bob
```

Navigate to the build folder and run cmake

```sh
cmake -G "Virtual Studio 17 2022" /path/to/src
```

# Preview

![Demo](https://i.imgur.com/XW7HoY5.png)

# Contribute

There are several TODO tags all over the source code, the project also is in desperate need of proper testing suites for both x86_64 and x64 architectures that can both be simulated using llvm.
Milestones
 - Win32 Architecture test pipeline
 - Naive shellcode replacement for asmjit
 - Linux support
