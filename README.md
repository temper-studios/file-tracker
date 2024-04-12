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

Common case:
You have a set of files you are working on in a directory. Navigate to this directory
and do:

```bash
fit create_track_all_save store  
```

This creates a `file store` called `store.fit`. 
The `file store` is then told to track all files in the directory. 
It then saves these files into the `file store`.

You can continue working on your files. When it comes time to save, just do 

```bash
fit save store.fit
```

This saves the current state of the tracked files in the `file store`. 

You can see what files are tracked by the file store by doing.

```bash
fit tracklist store.fit
```

Goals:
- Minimal set of commands that make intuitive sense and are easy to remember.
- Emphasis on telling the user exactly what is going on and what state they are in at all times. Doesn't hate the user.
- API designed for external tooling, like GUIs.
- Can be used programmatically. Is just a C header. 
- Designed for solo game devs or small teams.

And yes, the irony of using github is not lost on me.
