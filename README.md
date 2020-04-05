# urm
Ur Management Tool

# Virtual Environment

## Activate and Dectivate

I don't use a bin/activate script. Instead, I use shell macros:

    activate () {
        export VIRTUAL_ENV="$(pwd -P)"
        _OLD_VIRTUAL_PATH="$PATH"
        PATH="$VIRTUAL_ENV/bin:$PATH"
        hash -r
        _OLD_VIRTUAL_PROMPT="$PROMPT"
        PROMPT="%{%B%F{cyan}%}py:$(basename $VIRTUAL_ENV)%{%f%b%} $PROMPT"
    }

    deactivate () {
        if [ -n "$_OLD_VIRTUAL_PATH" ]
        then
            PATH="$_OLD_VIRTUAL_PATH"
            unset _OLD_VIRTUAL_PATH
        fi
        hash -r
        if [ -n "$_OLD_VIRTUAL_PROMPT" ]
        then
            PS1="$_OLD_VIRTUAL_PROMPT"
            unset _OLD_VIRTUAL_PROMPT
        fi
        unset VIRTUAL_ENV
        unset PYTHONHOME
        unset PYTHONPATH
    }

## Requirements

I want to rely as much as possible on Debian packages instead of pip, so I
don't have install_requires in setup.py or a requirements.txt file.

So, some manual setup will be required:
    sudo apt-get install python3-paramiko
    sudo apt-get install python3-lxml
    sudo apt-get install python3-dnspython

You can install these using pip3, too: paramiko lxml dnspython3

## Install self

I want to be able to edit in the source directory, so I use -e *after* running
activate:

    pip3 install -e .

Then, when activated, "urm" will work. Alternatively, ~/.local/bin/urm will
also work. This can be linked from ~/bin/urm so that activate and deactivate
are not required.

I realize this is not best practice, but when I have an NFS-shared source
directory, all I have to do on a new machine is to activate and run "pip3
install -e ." and do the required apt-get installations to have something
running. This is often easier and faster than installing the dependencies to
have pip3 do a full build on the dependent packages.

