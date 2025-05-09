# Assessment and static analysis

Initial assessment serves determining what tools and analysis methods will be required. This process also helps in the creation of a strategy for analysing the file. This requires carrying out a light static analysis.

## Origins

One of the purposes of reverse engineering is to help network administrators prevent similar malware from infiltrating a network. Knowing where a file came from could be helpful in securing the channel used to transmit it. For example, if the file being analysed was an email attachment, network administrators should secure the email server.

## Existing information

Searching the internet for already existing information can be very helpful. There might be existing analyses that has been done on the file, and determine what behaviours to expect.

## Viewing the file and extracting its text strings

Using tools like `file` to view the file help determine the type of file. Extracting readable text from the file with `strings` also gives hints of what messages, functions, and modules it will use when opened or executed.

## File information

The type of file is the most important piece of information that sets off the whole analysis. If the file type is a Windows executable, a preset of PE tools will be prepared. If the file type is a Word document, a sandbox environment will have to be installed with Microsoft Office and analysis tools that can read the OLE file format. If the given target for analysis is a website, preparations are likely to involve browser tools that can read HTML and debug Java scripts or Visual Basic scripts.

## Static analysis

Static analysis will help us make notes of what we will do during dynamic analysis. With knowledge of the assembly language, a disassembled file and its branches can be understood. This allows for preparing the right tools to read, open, and debug the file based on its file type, and understand the file's structure based on its [file format](../binary/README.md).