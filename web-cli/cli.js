document.addEventListener('DOMContentLoaded', () => {
    const output = document.getElementById('output');
    const commandInput = document.getElementById('command-input');

    // Command history
    let commandHistory = [];
    let historyIndex = -1;

    // Available commands
    const commands = {
        help: () => {
            return `
Available commands:
- help: Show this help message
- clear: Clear the screen
- echo [text]: Print the text
- hello: Print a hello world message
            `;
        },
        clear: () => {
            output.innerHTML = '';
            return '';
        },
        echo: (args) => {
            return args.join(' ');
        },
        hello: () => {
            return 'Hello, World!';
        }
    };

    // Add command to output
    function addCommandToOutput(command, result) {
        const commandDiv = document.createElement('div');
        commandDiv.className = 'command-line';
        commandDiv.innerHTML = `<span class="prompt">$</span> ${command}`;
        output.appendChild(commandDiv);

        if (result) {
            const resultDiv = document.createElement('div');
            resultDiv.className = 'command-result';
            resultDiv.textContent = result;
            output.appendChild(resultDiv);
        }

        output.scrollTop = output.scrollHeight;
    }

    // Handle command execution
    function executeCommand(input) {
        const [command, ...args] = input.trim().split(' ');
        
        if (command === '') {
            return;
        }

        if (commands[command]) {
            const result = commands[command](args);
            addCommandToOutput(input, result);
        } else {
            addCommandToOutput(input, `Command not found: ${command}`);
        }
    }

    // Handle input
    commandInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const command = commandInput.value;
            commandHistory.push(command);
            historyIndex = commandHistory.length;
            executeCommand(command);
            commandInput.value = '';
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (historyIndex > 0) {
                historyIndex--;
                commandInput.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                commandInput.value = commandHistory[historyIndex];
            } else {
                historyIndex = commandHistory.length;
                commandInput.value = '';
            }
        }
    });
}); 