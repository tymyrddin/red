# WebAssembly (WASM)

WebAssembly, also called Wasm, is a Web-optimized code format and API (Application Programming Interface) that can improve the performances and capabilities of websites. Version 1.0 of WebAssembly was released in 2017, and became an official W3C standard in 2019.

The standard is actively supported by all major browser suppliers. The official list of **inside the browser** use cases mentions video editing, 3D games, virtual and augmented reality, p2p services, and scientific simulations. Besides making browsers much more powerful than JavaScript could, this standard may even extend the lifespan of websites.

WebAssembly is currently being used in mobile and edge based environments with such products as Cloudflare Workers.

Files in `.wasm` format contain low level binary instructions (bytecode), executable at **near CPU-native speed** by a virtual machine that uses a common stack. The code is packaged in modules, objects that are directly executable by a browser, and each module can be instantiated multiple times. The functions defined inside modules are listed in one dedicated array, or Table, and the corresponding data are contained in another structure, called arraybuffer. Developers can explicitly allocate memory for `.wasm` code with the Javascript `WebAssembly.memory()` call.

## Resources

* [WebAssembly](https://webassembly.org/)

