import './styles.css';
import { Aptos, AptosConfig, Network, Account, AccountAddress, Ed25519PrivateKey } from "@aptos-labs/ts-sdk";

// Global constants
const config = new AptosConfig({ network: Network.DEVNET });
const aptos = new Aptos(config);
const CONTRACT_ADDRESS = '0x5f029e0d35407745f47f89d1d0e5bf9ba3c0ca1cce8de0fd0260a56382684b97';

interface SavedAccount {
    address: string;
    privateKeyHex: string;
    publicKeyHex: string;
}

class GameApp {
    private loadedAccount: SavedAccount | null = null;
    private loadedRoom: string | null = null;
    private loginDialog: HTMLElement | null;
    private newAccountBtn: HTMLElement | null;
    private savedAccountBtn: HTMLElement | null;
    private currentAccount: Account | null = null;
    private createTableBtn: HTMLButtonElement | null;
    private findTableBtn: HTMLButtonElement | null;
    private leaveTableBtn: HTMLButtonElement | null;
    private getSeatedBtn: HTMLButtonElement | null;
    private lobbyView: HTMLElement | null;
    private tableView: HTMLElement | null;
    private hostDialog: HTMLElement | null;
    private contractStatusLabel: HTMLElement | null;
    private curAccountLabel: HTMLElement | null;
    private balanceLabel: HTMLElement | null;
    private startGameBtn: HTMLButtonElement | null;
    private cancelHostBtn: HTMLButtonElement | null;
    private allowedAddressesInput: HTMLTextAreaElement | null;
    private roomAddress: string | null = null;
    private tableBrief: any | null;
    private client: Aptos;
    private tablePolling: any | null;
    private roomAddressLabel: any | null;
    private myBetAmount: HTMLInputElement | null;
    private betBtn: HTMLButtonElement | null;
    private testBtn: HTMLButtonElement | null;
    constructor() {
        // Initialize UI.
        this.tablePolling = null;
        this.tableBrief = null;
        this.contractStatusLabel = document.getElementById('contract-status');
        this.curAccountLabel = document.getElementById('cur-account-status');
        this.roomAddressLabel = document.getElementById('room-address');
        this.balanceLabel = document.getElementById('balance-status');
        this.loginDialog = document.getElementById('login-dialog');
        this.newAccountBtn = document.getElementById('new-account-btn');
        this.newAccountBtn!.addEventListener('click', () => this.handleNewAccount());
        this.savedAccountBtn = document.getElementById('saved-account-btn');
        this.savedAccountBtn!.addEventListener('click', () => this.handleSavedAccountClick());
        this.createTableBtn = document.getElementById('create-table-btn') as HTMLButtonElement;
        this.createTableBtn!.addEventListener('click', () => this.showCreateTableDialog());
        this.findTableBtn = document.getElementById('find-table-btn') as HTMLButtonElement;
        this.findTableBtn!.addEventListener('click', () => this.handleFindTable());
        this.leaveTableBtn = document.getElementById('leave-table-btn') as HTMLButtonElement;
        this.leaveTableBtn?.addEventListener('click', () => this.handleLeaveTable());
        this.getSeatedBtn = document.getElementById('get-seated-btn') as HTMLButtonElement;
        this.getSeatedBtn?.addEventListener('click', () => this.handleGetSeated());
        this.lobbyView = document.getElementById('lobby-view');
        this.tableView = document.getElementById('table-view');
        this.hostDialog = document.getElementById('host-dialog');
        this.startGameBtn = document.getElementById('start-game-btn') as HTMLButtonElement;
        this.startGameBtn!.addEventListener('click', () => this.handleStartGame());
        this.cancelHostBtn = document.getElementById('cancel-host-btn') as HTMLButtonElement;
        this.cancelHostBtn!.addEventListener('click', () => this.hideHostDialog());
        this.allowedAddressesInput = document.getElementById('allowed-addresses') as HTMLTextAreaElement;
        this.client = aptos;
        
        this.betBtn = document.getElementById('bet-or-raise-btn') as HTMLButtonElement;
        this.myBetAmount = document.getElementById('my-bet-amount') as HTMLInputElement;
        this.myBetAmount!.addEventListener('input', () => this.handleMyBetAmountChange());
        this.testBtn = document.getElementById('test-btn') as HTMLButtonElement;
        this.testBtn!.addEventListener('click', () => this.handleTestBtn());
        
        // Check for saved account
        this.loadedAccount = this.loadSavedAccount();
        this.loadedRoom = localStorage.getItem('LAST_ROOM');
        if (this.savedAccountBtn) {
            this.savedAccountBtn.addEventListener('click', () => this.handleSavedAccountClick());
            if (this.loadedAccount) {
                const shortAccount = this.loadedAccount.address.slice(0, 6) + '...' + this.loadedAccount.address.slice(-4);
                if (this.loadedRoom) {
                    const shortRoom = this.loadedRoom.slice(0, 6) + '...' + this.loadedRoom.slice(-4);
                    this.savedAccountBtn.textContent = `Continue as ${shortAccount} and return to room ${shortRoom}`;
                } else {
                    this.savedAccountBtn.textContent = `Continue as ${shortAccount}`;
                }
            } else {
                this.savedAccountBtn.style.display = 'none';
            }
    
    
        }
        
        // Start poker room polling immediately
        this.startContractPingLoop();
        this.setDisplayNoneForAllGameContentVariants();
        this.tableView!.style.display = 'flex';
    }
    handleTestBtn(): any {
        document.getElementById('player-5-box')!.classList.add('player-turn');
        document.getElementById('player-4-box')!.classList.remove('player-turn');
    }
    private handleMyBetAmountChange(): any {
        const currentValue = parseInt(this.myBetAmount!.value, 10);
        const allowedValues = [29, 40, 50, 60, 70, 80, 90, 100];
        const closestValue = allowedValues.reduce((prev: number, curr: number) => {
            return (Math.abs(curr - currentValue) < Math.abs(prev - currentValue) ? curr : prev);
        });
        this.myBetAmount!.value = closestValue.toString();
        this.betBtn!.textContent = closestValue == 29 ? 'CHECK' : closestValue == 100 ? 'ALL IN' : 'Bet ' + closestValue;
    }

    private loadSavedAccount(): SavedAccount | null {
        const item = localStorage.getItem("SAVED_ACCOUNT");
        if (!item) return null;
        try {
            const parsed = JSON.parse(item);
            return parsed as SavedAccount;
        } catch {
            return null;
        }
    }

    private async handleSavedAccountClick() {
        const privateKeyHex = this.loadedAccount!.privateKeyHex.replace('0x', '');
        const privateKeyBytes = new Uint8Array(privateKeyHex.length / 2);
        for (let i = 0; i < privateKeyHex.length; i += 2) {
            privateKeyBytes[i / 2] = parseInt(privateKeyHex.substring(i, i + 2), 16);
        }
        const account = Account.fromPrivateKey({
            privateKey: new Ed25519PrivateKey(privateKeyBytes)
        });

        this.currentAccount = account;

        // Update UI.
        this.loginDialog!.style.display = 'none';
        this.curAccountLabel!.textContent = `Account: ${this.currentAccount!.accountAddress.toString()}`;
        this.balanceLabel!.textContent = `Balance: fetching...`;
        this.startBalancePolling();

        if (this.loadedRoom) {
            this.onEnteringGameRoom();
        } else {
            this.onEnteringLobby();
        }
    }

    private onEnteringLobby() {
        this.setDisplayNoneForAllGameContentVariants();
        this.lobbyView!.style.display = 'flex'; 
    }

    private async handleNewAccount() {
        // Generate new account
        const newAccount = Account.generate();
        
        // Save account data
        const accountData: SavedAccount = {
            address: newAccount.accountAddress.toString(),
            privateKeyHex: newAccount.privateKey.toString(),
            publicKeyHex: newAccount.publicKey.toString()
        };
        
        localStorage.setItem('SAVED_ACCOUNT', JSON.stringify(accountData));
        
        this.currentAccount = newAccount;
        
        this.loginDialog!.style.display = 'none';
        this.curAccountLabel!.textContent = `Account: ${newAccount.accountAddress.toString()}`;
        this.balanceLabel!.textContent = `Balance: fetching...`;
        this.startBalancePolling();
    }

    private async startBalancePolling() {
        while (true) {
            try {
                const balanceInOctas = await this.client.getAccountAPTAmount({
                    accountAddress: this.currentAccount!.accountAddress
                });

                const balanceInAPT = Number(balanceInOctas) / 100000000;
                this.balanceLabel!.textContent = `Balance: ${balanceInAPT.toString()} APT`;
            } catch (error) {
                this.balanceLabel!.textContent = 'Balance: ERROR';
            }
            await new Promise(r => setTimeout(r, 5000));
        }
    }

    private showCreateTableDialog() {
        if (this.hostDialog) {
            this.hostDialog.style.display = 'flex';
            // Pre-fill the textbox with host's address
            if (this.allowedAddressesInput && this.currentAccount) {
                this.allowedAddressesInput.value = this.currentAccount.accountAddress.toString();
            }
        }
    }

    private hideHostDialog() {
        if (this.hostDialog) {
            this.hostDialog.style.display = 'none';
        }
    }

    private async handleStartGame() {
        if (!this.allowedAddressesInput || !this.currentAccount) return;

        const addresses = this.allowedAddressesInput.value
            .split('\n')
            .map(addr => addr.trim())
            .filter(addr => addr.length > 0)
            .map(addr => this.normalizeAddress(addr));

        // Add host's address to the list if not already included
        const hostAddress = this.currentAccount.accountAddress.toString();
        if (!addresses.includes(hostAddress)) {
            addresses.unshift(hostAddress);
        }

        // Generate random 32-byte seed
        const seed = new Uint8Array(32);
        crypto.getRandomValues(seed);

        // Construct payload
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount.accountAddress,
            data: {
                function: `${CONTRACT_ADDRESS}::poker_room::create`,
                typeArguments: [],
                functionArguments: [
                    seed,
                    addresses.map(addr => AccountAddress.fromString(addr))
                ]
            }
        });
        
        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount,
            transaction: txn
        });
        var committedTxn: any;
        try {
            committedTxn = await this.client.transaction.submit.simple({
                transaction: txn,
                senderAuthenticator: signedTxn
            });
        } catch (e) {
            alert('Error submitting create room transaction: ' + e);
            console.error('Error submitting create room transaction:', e);
            return;
        }

        // Wait for transaction
        await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        const txnDetails = await this.client.getTransactionByHash({ transactionHash: committedTxn.hash });
        console.log(txnDetails);
        
        if (!txnDetails) {
            throw new Error('Transaction details not found');
        }

        // Extract room address from events
        const events = (txnDetails as any).events || [];
        const roomCreatedEvent = events.find(
            (e: any) => e.type === `${CONTRACT_ADDRESS}::poker_room::RoomCreatedEvent`
        );
        
        if (!roomCreatedEvent) {
            throw new Error('Room creation event not found');
        }

        this.roomAddress = roomCreatedEvent.data.room_addr;

        this.hideHostDialog();
        this.onEnteringGameRoom();
    }

    private async handleFindTable() {
        // Prompt for room address
        const roomAddress = prompt('Enter room address:');
        if (!roomAddress) return;

        // Normalize the address
        const normalizedAddress = this.normalizeAddress(roomAddress);
        if (!this.isValidAddress(normalizedAddress)) {
            alert('Invalid room address');
            return;
        }

        // Start polling the room status
        this.onEnteringGameRoom();
    }

    private normalizeAddress(address: string): string {
        // Remove '0x' prefix if present
        let cleanAddr = address.toLowerCase().replace('0x', '');
        
        // Pad with zeros to make it 64 characters (32 bytes)
        cleanAddr = cleanAddr.padStart(64, '0');
        
        // Add '0x' prefix back
        return `0x${cleanAddr}`;
    }

    private isValidAddress(address: string): boolean {
        // Accept any hex string and normalize it
        return /^(0x)?[0-9a-fA-F]+$/.test(address);
    }

    private createTablePolling() {
        let shouldStop = false;
        return {
            start: async () => {
                while (!shouldStop) {
                    try {
                        const result = await this.client.view({
                            payload: {
                                function: `${CONTRACT_ADDRESS}::poker_room::get_room_brief`,
                                typeArguments: [],
                                functionArguments: [this.roomAddress!]
                            }
                        });
                        this.tableBrief = result[0];
                        this.updateTableViews();
                    } catch (error) {
                    }
            
                    await new Promise(r => setTimeout(r, 5000));
                }
            },
            stop: () => {
                shouldStop = true;
            }
        };
    }
    private updateTableViews() {
        for (let i = 0; i < this.tableBrief.expected_player_addresses.length; i++) {
            document.getElementById(`player-${i}-addr`)!.textContent = this.tableBrief.expected_player_addresses[i];
            document.getElementById(`player-${i}-liveness`)!.textContent = this.tableBrief.player_livenesses[i];
            document.getElementById(`player-${i}-chips-in-hand`)!.textContent = this.tableBrief.player_chips[i];
            document.getElementById(`player-${i}-chips-in-pot`)!.textContent = '0';
            document.getElementById(`player-${i}-folded`)!.textContent = 'false';
            document.getElementById(`player-${i}-private-cards`)!.textContent = '';
            if (this.tableBrief.expected_player_addresses[i] == this.currentAccount?.accountAddress.toString()) {
                document.getElementById(`player-${i}-get-seated`)!.textContent = 'Sit here';
            }
        }
    }

    private async startContractPingLoop() {
        while (true) {
            try {
                const result = await this.client.view({
                    payload: {
                        function: `${CONTRACT_ADDRESS}::poker_room::about`,
                        typeArguments: [],
                        functionArguments: []
                    }
                });
    
                this.contractStatusLabel!.textContent = 'contract: OK(' + result[0] + ')';
            } catch (error) {
                this.contractStatusLabel!.textContent = 'contract: unhealthy!';
            }

            await new Promise(r => setTimeout(r, 10000));
        }
    }

    private onEnteringGameRoom() {
        // Update views.
        this.setDisplayNoneForAllGameContentVariants();
        this.tableView!.style.display = 'block';
        this.roomAddressLabel!.textContent = `Table address: ${this.roomAddress!}`;
        this.tablePolling = this.createTablePolling();
        this.tablePolling.start();
    }

    private setDisplayNoneForAllGameContentVariants() {
        this.lobbyView!.style.display = 'none';
        this.tableView!.style.display = 'none';
    }

    private async handleGetSeated() {
        try {
            // Construct payload
            const txn = await this.client.transaction.build.simple({
                sender: this.currentAccount!.accountAddress,
                data: {
                    function: `${CONTRACT_ADDRESS}::poker_room::join`,
                    typeArguments: [],
                    functionArguments: [this.roomAddress!]
                }
            });
            
            const signedTxn = this.client.transaction.sign({
                signer: this.currentAccount!,
                transaction: txn
            });
            
            this.getSeatedBtn!.textContent = 'Joining...';
            this.getSeatedBtn!.disabled = true;
            // Submit transaction without waiting
            
            const committedTxn = await this.client.transaction.submit.simple({
                transaction: txn,
                senderAuthenticator: signedTxn
            });
            
            console.log('Join transaction submitted:', `https://explorer.aptoslabs.com/txn/${committedTxn.hash}?network=devnet`);
        } catch (error) {
            console.error('Error submitting join transaction:', error);
        }
    }

    private handleLeaveTable() {
        this.tablePolling.stop();
        this.tablePolling = null;
        this.tableBrief = null;
        this.setDisplayNoneForAllGameContentVariants();
        this.lobbyView!.style.display = 'flex';
        localStorage.removeItem('LAST_ROOM');
    }
}

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new GameApp();
});
