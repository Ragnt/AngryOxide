prog := angryoxide
bash_completion_script := completions/bash_angryoxide_completions
zsh_completion_script := completions/zsh_angryoxide_completions

debug ?=

ifdef debug
  release :=
  target := debug
  extension := debug
else
  release := --release
  target := release
  extension :=
endif

BASH_COMPLETION_DIR := /etc/bash_completion.d
ZSH_COMPLETION_DIR := /home

build:
	cargo build $(release)

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "This operation must be run as root. Please use sudo." >&2; \
		exit 1; \
	fi

install-binary: check-root
	cp target/$(target)/$(prog) /usr/bin/$(prog)

install-bash: check-root
	@if [ -x "$$(command -v bash)" ]; then \
		echo "Installing bash completion for $(prog)..."; \
		mkdir -p $(BASH_COMPLETION_DIR); \
		cp $(bash_completion_script) $(BASH_COMPLETION_DIR)/$(prog); \
		echo "Bash completion installed successfully."; \
	else \
		echo "Bash not found, skipping Bash completion installation."; \
	fi

install-zsh: check-root
	@if [ -x "$$(command -v zsh)" ]; then \
		echo "Installing zsh completion for $(prog) for all users..."; \
		for dir in $(ZSH_COMPLETION_DIR)/*; do \
			if [ -d "$$dir" ]; then \
				user=$$(basename $$dir); \
				zsh_dir="$$dir/.zsh/completion"; \
				echo "Installing for user $$user..."; \
				mkdir -p $$zsh_dir; \
				cp $(zsh_completion_script) $$zsh_dir/_$(prog); \
				chown $$user:$$user $$zsh_dir/_$(prog); \
			fi \
		done; \
		echo "Zsh completion installed successfully for all users."; \
	else \
		echo "Zsh not found, skipping Zsh completion installation."; \
	fi

install: install-binary install-bash install-zsh
 
help:
	@echo "usage: make [debug=1]"

uninstall:
	rm -f /usr/bin/$(prog)
	@rm -f $(BASH_COMPLETION_DIR)/$(prog)
	@for dir in $(ZSH_COMPLETION_DIR)/*; do \
		if [ -d "$$dir" ]; then \
			rm -f "$$dir/.zsh/completion/_$(prog)"; \
		fi \
	done; \
	echo "Cleaned installed binary and completion scripts."
