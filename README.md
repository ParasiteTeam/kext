# Parasite
## Powerful Code Insertion Platform for OS X

### What this fork adds
This fork adds compatibility with Opee for those who do not want to patch Foundation and are comfortable using an unsigned kernel extension.

Changes:
1. Sets the payload to the OpeeLoader.dylib trampoline.

2. Uses LC_LOAD_WEAK_DYLIB so that apps do not crash if OpeeLoader.dylib is not present on the filesystem.

3. Injects into all processes instead of the Dock

Usage with Opee:
Follow all the installation instructions on the Opee page except for the part using optool. Then load this kext.

### Intro
Parasite allows you to change the expected behavior of apps and stuff. Sounds scary.

### How do I Parasite?
If you are experienced enough you'll know how to use it. If not, keep out for your own safety.

### How do I get?
Compile it for yourself.

### How do I compile?
You should know that. :P

### License?
Pretty much the BSD license, just don't repackage it and call it your own please!

Also if you do make some changes, feel free to make a pull request and help make things more awesome!

### Contact Info?
If you have any support requests please feel free to email me at shinvou[at]gmail[dot]com.

Otherwise, feel free to follow me on twitter: [@biscoditch](https:///www.twitter.com/biscoditch)!

### Special Thanks
Thanks to [@osxreverser](https:///www.twitter.com/osxreverser). ATM I use slightly modified code (userspace injection/kernel solving) from his project [mario](https://github.com/gdbinit/mario).
