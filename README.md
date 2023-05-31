# Basic x64 Manual Mapper
This is a basic manual mapper is capable of loading a DLL into another Process

## Features
- Copy Section
- Resolve Relocation
- Resolve Imports
- Fix Protection
- Execute code via IAT


## TODO
- Fix TLS

## How to use
1. Create mapper object
2. Select the file giving it a dll path
3. Select a process 
4. Call map image

# How to use it
[Example](https://github.com/AdamFilet/ManualMapper/blob/main/entry.cpp)
