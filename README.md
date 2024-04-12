# file-tracker (fit)
Git is an actively hostile piece of software. This is the replacement.
The hotter, better looking, cousin of git.

This recognises that command line interfaces are fundamentally stupid 
and tries to mitigate some of the problems with them. 

Ideally, this should be used with a GUI.

This is very early days. Subject to changes.

Features:
- Can create a store which stores tracked files.
- Files are only saved when they change.
- Can specify a snapshot to load from the store.

e.g.
```c
fit create store                // creates a file store that will be used to store and track files.
fit track store.fit myfile1.txt // specifies we would like initially have the store.fs track the myfile1.txt file.
fit track store.fit myfile2.txt // track more than one file
fit save store.fit              // Takes a snapshot of all tracked files and saves them to the file store
fit load store.fit 1            // Loads snapshot 1 from the file store into your directory.
```

Goals:
- Minimal set of commands that make intuitive sense and are easy to remember.
- Emphasis on telling the user exactly what is going on and what state they are in at all times. Doesn't hate the user.
- API designed for external tooling, like GUIs.
- Can be used programmatically. Is just a C header. 
- Designed for solo game devs or small teams.

And yes, the irony of using github is not lost on me.
