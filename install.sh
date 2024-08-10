#!/bin/bash

prog="angryoxide"
bash_completion_script="completions/bash_angryoxide_completions"
zsh_completion_script="completions/zsh_angryoxide_completions"
BASH_COMPLETION_DIR="/etc/bash_completion.d"
ZSH_COMPLETION_DIR="/home"

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "This operation must be run as root. Please use sudo." >&2
        exit 1
    fi
}

install_binary() {
    check_root
    echo "Installing $prog binary..."
    chmod +x $prog
    cp "$prog" "/usr/bin/$prog"
}

install_bash() {
    check_root
    if command -v bash &> /dev/null; then
        echo "Installing bash completion for $prog..."
        mkdir -p "$BASH_COMPLETION_DIR"
        cp "$bash_completion_script" "$BASH_COMPLETION_DIR/$prog"
        echo "Bash completion installed successfully."
    else
        echo "Bash not found, skipping Bash completion installation."
    fi
}

install_zsh() {
    check_root
    if command -v zsh &> /dev/null; then
        echo "Installing zsh completion for $prog for all users..."
        for dir in $ZSH_COMPLETION_DIR/*; do
            if [[ -d "$dir" ]]; then
                user=$(basename "$dir")
                zsh_dir="$dir/.zsh/completion"
                echo "Installing for user $user..."
                mkdir -p "$zsh_dir"
                cp "$zsh_completion_script" "$zsh_dir/_$prog"
                chown "$user:$user" "$zsh_dir/_$prog"
            fi
        done
        echo "Zsh completion installed successfully for all users."
    else
        echo "Zsh not found, skipping Zsh completion installation."
    fi
}

uninstall() {
    check_root
    echo "Uninstalling $prog..."
    rm -f "/usr/bin/$prog"
    rm -f "$BASH_COMPLETION_DIR/$prog"
    for dir in $ZSH_COMPLETION_DIR/*; do
        if [[ -d "$dir" ]]; then
            rm -f "$dir/.zsh/completion/_$prog"
        fi
    done
    echo "Cleaned installed binary and completion scripts."
}

case "$1" in
    install)
        install_binary
        install_bash
        install_zsh
        ;;
    uninstall)
        uninstall
        ;;
    *)
        install_binary
        install_bash
        install_zsh
        ;;
esac
