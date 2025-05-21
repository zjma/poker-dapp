import './styles.css';
import { Aptos, AptosConfig, Network, Account, AccountAddress, Ed25519PrivateKey, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { PokerRoomStateBrief } from './poker_room';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { STATE_IN_PROGRESS } from './crypto/dkg_v0';
import { sha3_256 } from '@noble/hashes/sha3';

// Global constants
const config = new AptosConfig({ network: Network.DEVNET });
const aptos = new Aptos(config);
const CONTRACT_ADDRESS = '0xb4417d6b6b1dd8743cb7c44fd75c401065d86e97df49474b39c8ce77747fab17';

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
    private tableBrief: PokerRoomStateBrief | null;
    private client: Aptos;
    private tablePolling: any | null;
    private roomAddressLabel: any | null;
    private myBetAmount: HTMLInputElement | null;
    private allowedBetAmounts: number[] = [0, 100];
    private betBtn: HTMLButtonElement | null;
    private refreshBtn: HTMLButtonElement | null;
    private stepBtn: HTMLButtonElement | null;
    private loadingSpinner: HTMLElement | null = null;
    private mySitBtn: HTMLButtonElement | null;

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
        this.startGameBtn!.addEventListener('click', () => this.handleCreateRoom());
        this.cancelHostBtn = document.getElementById('cancel-host-btn') as HTMLButtonElement;
        this.cancelHostBtn!.addEventListener('click', () => this.hideHostDialog());
        this.allowedAddressesInput = document.getElementById('allowed-addresses') as HTMLTextAreaElement;
        this.client = aptos;
        
        this.betBtn = document.getElementById('bet-or-raise-btn') as HTMLButtonElement;
        this.myBetAmount = document.getElementById('my-bet-amount') as HTMLInputElement;
        this.myBetAmount!.addEventListener('input', () => this.handleMyBetAmountChange());
        
        this.refreshBtn = document.getElementById('refresh-btn') as HTMLButtonElement;
        this.refreshBtn!.addEventListener('click', () => this.handleRefreshBtn());

        this.stepBtn = document.getElementById('step-btn') as HTMLButtonElement;
        this.stepBtn!.addEventListener('click', () => this.handleStepBtn());

        this.loadingSpinner = document.getElementById('loading-spinner');
        this.mySitBtn = document.getElementById('my-sit-button') as HTMLButtonElement;
        this.mySitBtn!.addEventListener('click', () => this.handleMySit());
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
        this.loginDialog!.style.display = 'flex';

    }
    private async handleStepBtn() {
        const {secretShare, contribution} = this.tableBrief!.curDKGSession!.generateContribution();
        
        localStorage.setItem(`rooms/${this.roomAddress}/dkgs/${this.tableBrief!.numDKGsDone}/secretShare`, bytesToHex(secretShare.toBytes()));
        
        const serializer = new Serializer();
        contribution.encode(serializer);
        const contributionBytes = serializer.toUint8Array();

        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${CONTRACT_ADDRESS}::poker_room::process_dkg_contribution`,
                typeArguments: [],
                functionArguments: [
                    this.roomAddress!,
                    this.tableBrief!.numDKGsDone,
                    contributionBytes,
                ]
            }
        });

        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount!,
            transaction: txn
        });

        const committedTxn = await this.client.transaction.submit.simple({
            transaction: txn,
            senderAuthenticator: signedTxn
        });

        const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        if (txnResponse.success) {
            await this.refreshRoomStatus();
        } else {
            alert('Error submitting dkg contribution transaction: ' + txnResponse.vm_status);
        }
    }

    private async handleMySit() {
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
        var committedTxn: any;
        try {
            committedTxn = await this.client.transaction.submit.simple({
                transaction: txn,
                senderAuthenticator: signedTxn
            });
        } catch (e) {
            console.error('Error submitting create room transaction:', e);
            return;
        }

        this.loadingSpinner!.style.display = 'block';

        const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        if (txnResponse.success) {
            await this.refreshRoomStatus();
        } else {
            alert('Error submitting join transaction: ' + txnResponse.vm_status);
        }
    }

    /**
     * Trigger any pending state transition, then call the view function to get the latest room status.
     * Update UI and schedule new tasks based on the new room status.
     * 
     * @returns 
     */
    private async refreshRoomStatus() {
        this.loadingSpinner!.style.display = 'block';

        // Construct payload
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${CONTRACT_ADDRESS}::poker_room::state_update`,
                typeArguments: [],
                functionArguments: [this.roomAddress!]
            }
        });
        
        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount!,
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
        const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        if (!txnResponse.success) {
            alert('Error submitting state update transaction: ' + txnResponse.vm_status);
            return;
        }
        
        // Fetch the latest room status
        const roomBrief = await this.fetchRoomStatus();

        // Update UI
        this.tableBrief = roomBrief;
        this.updateTableViews(roomBrief);
        this.loadingSpinner!.style.display = 'none';

        // Schedule next task
        this.performDKGActions();
        this.performDeckgenActions();
    }


    private async handleRefreshBtn() {
        await this.refreshRoomStatus();
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
            this.roomAddress = this.loadedRoom;
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
        this.lobbyView!.style.display = 'flex';
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
            await new Promise(r => setTimeout(r, 30000));
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

    private async handleCreateRoom() {
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

        this.roomAddress = normalizedAddress;
        localStorage.setItem('LAST_ROOM', normalizedAddress);
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

    private async fetchRoomStatus(): Promise<PokerRoomStateBrief> {
        const result = await this.client.view({
            payload: {
                function: `${CONTRACT_ADDRESS}::poker_room::get_room_brief_bcs`,
                typeArguments: [],
                functionArguments: [this.roomAddress!]
            }
        });
        const hex = result[0] as string;
        const deserializer = new Deserializer(hexToBytes(hex.startsWith('0x') ? hex.slice(2) : hex));
        const brief = PokerRoomStateBrief.decode(deserializer);
        console.log(brief);
        return brief;
    }

    private updateTableViews(roomBrief: PokerRoomStateBrief) {
        console.log(roomBrief);
        this.roomAddressLabel!.textContent = `${this.roomAddress!}`;
        var myPlayerIdx = roomBrief.expectedPlayerAddresses.findIndex(addr => addr.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) myPlayerIdx = 0;
        const numUiSeats = 8;
        const numPlayers = roomBrief.expectedPlayerAddresses.length;
        const viewIdxsByPlayerIdx = Array.from({length: numPlayers}, (_, playerIdx) => Math.round((playerIdx + numPlayers - myPlayerIdx) % numPlayers * numUiSeats / numPlayers));
        for (let rivalNumber = 0; rivalNumber < numUiSeats; rivalNumber++) {
            const playerIdx = viewIdxsByPlayerIdx.findIndex(viewIdx => viewIdx == rivalNumber);
            const viewPrefix = rivalNumber == 0 ? 'my' : `rival-${rivalNumber}`;
            const curBox = document.getElementById(`${viewPrefix}-box`);
            const awayFlag = document.getElementById(`${viewPrefix}-away-flag`);
            if (playerIdx == -1) {
                curBox!.style.display = 'none';
                awayFlag!.style.display = 'none';
            } else {
                curBox!.style.display = 'block';
                if (roomBrief.playerLivenesses[playerIdx]) {
                    curBox!.classList.remove('player-away');
                    curBox!.classList.add('player-at-table');   
                    awayFlag!.style.display = 'none';
                } else {
                    curBox!.classList.remove('player-at-table');
                    curBox!.classList.add('player-away');
                    awayFlag!.style.display = 'flex';
                }
                const curPlayerAddr = roomBrief.expectedPlayerAddresses[playerIdx];
                document.getElementById(`${viewPrefix}-addr`)!.textContent = rivalNumber == 0 ? "You" : curPlayerAddr.toString().slice(0, 4) + '...' + curPlayerAddr.toString().slice(-4);
                document.getElementById(`${viewPrefix}-chips-in-hand`)!.textContent = '🪙 ' + (roomBrief.state == 4 ? roomBrief.curHand!.chipsInHand[playerIdx] : roomBrief.playerChips[playerIdx]);
                document.getElementById(`${viewPrefix}-dealer-light`)!.style.display = roomBrief.state == 4 && roomBrief.curHand!.players[0] == curPlayerAddr? 'block' : 'none';
                document.getElementById(`${viewPrefix}-bet`)!.textContent = roomBrief.state == 4 ? roomBrief.curHand!.bets[playerIdx].toString() : '';
                document.getElementById(`${viewPrefix}-private-cards-area`)!.style.display = 'none';
                let privateCardsArea = document.getElementById(`${viewPrefix}-private-cards-area`);
                if (roomBrief.state == 4 && roomBrief.curHand!.state != 140658) {
                    privateCardsArea!.style.display = 'block';
                    for (let privateCardIdx = 0; privateCardIdx < 2; privateCardIdx++) {
                        const card = roomBrief.curHand!.revealedPrivateCards[playerIdx*2+privateCardIdx];
                        const cardHolder = document.getElementById(`${viewPrefix}-card-${privateCardIdx}`);
                        cardHolder!.classList.remove('red-suit');
                        cardHolder!.classList.remove('card-back');
                        if (card) {
                            const cardText = this.cardTextFromCardIdx(card);
                            cardHolder!.textContent = cardText;
                            if (cardText[2] == '♥' || cardText[2] == '♦') {
                                cardHolder!.classList.add('red-suit');
                            }
                        } else {
                            cardHolder!.textContent = '';
                            cardHolder!.classList.add('card-back');
                        }
                    }
                } else {
                    privateCardsArea!.style.display = 'none';
                }
    
                if (rivalNumber == 0) {
                    // Self view
                    const betControls = document.getElementById(`${viewPrefix}-bet-decision-inputs`);
                    if (roomBrief.state == 4 && roomBrief.curHand!.state == 140855 && roomBrief.curHand!.currentActionPlayerIdx == playerIdx) {
                        betControls!.style.display = 'block';
                        const amountInput = document.getElementById(`${viewPrefix}-bet-amount`) as HTMLInputElement;
                        const maxBetOnTable = roomBrief.curHand!.bets.reduce((max: number, bet: number) => Math.max(max, bet), 0);
                        const myBet = roomBrief.curHand!.bets[playerIdx];
                        const myChipsInHand = roomBrief.curHand!.chipsInHand[playerIdx];
                        const minToAdd = Math.min(maxBetOnTable - myBet, myChipsInHand);
                        amountInput!.min = minToAdd.toString();
                        amountInput!.max = myChipsInHand.toString();
                        amountInput!.value = minToAdd.toString();
                        const minRaiseStep = roomBrief.curHand!.minRaiseStep;
                        this.allowedBetAmounts = Array.from({length: myChipsInHand - minToAdd + 1}, (_, i) => minToAdd + i).filter((amount) => amount == minToAdd || amount == myChipsInHand || amount >= minToAdd + minRaiseStep);
                    } else {
                        betControls!.style.display = 'none';
                    }

                    const mySitBtn = document.getElementById(`my-sit-button`);
                    if (roomBrief.playerLivenesses[playerIdx]) {
                        mySitBtn!.style.display = 'none';
                    } else {
                        mySitBtn!.style.display = 'flex';
                    }
                }    
            }
        }
        const inHandPublicInfo = document.getElementById('in-hand-public-info');
        const dkgOrShuffleInProgressFlag = document.getElementById('dkg-or-shuffle-in-progress-flag');
        if (roomBrief.state == 4) {
            inHandPublicInfo!.style.display = 'flex';
            dkgOrShuffleInProgressFlag!.style.display = 'none';
        } else {
            inHandPublicInfo!.style.display = 'none';
            dkgOrShuffleInProgressFlag!.style.display = 'flex';
        }
        
    }

    private cardTextFromCardIdx(cardIdx: number) {
        const cardValues = ['A', '2', '3', '4', '5', '6', '7', '8', '9', 'T', 'J', 'Q', 'K'];
        const cardSuits = ['♠', '♥', '♦', '♣'];
        return cardValues[cardIdx % 13] + cardSuits[Math.floor(cardIdx / 13)];
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
        this.loadingSpinner!.style.display = 'block';
        this.roomAddressLabel!.textContent = `${this.roomAddress!}`;
        // this.tablePolling = this.createTablePolling();
        // this.tablePolling.start();
        this.fetchRoomStatus().then((roomBrief) => {
            this.tableBrief = roomBrief;
            this.updateTableViews(roomBrief);
            this.setDisplayNoneForAllGameContentVariants();
            this.tableView!.style.display = 'block';
        });

    }

    private setDisplayNoneForAllGameContentVariants() {
        this.lobbyView!.style.display = 'none';
        this.tableView!.style.display = 'none';
        this.loadingSpinner!.style.display = 'none';
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

    private async performDeckgenActions() {
        const deckgenSession = this.tableBrief!.curDeckgenSession;
        if (deckgenSession == null) return;
        const deckgenIdx = this.tableBrief!.numDeckgensDone;
        const shuffle = deckgenSession.shuffle;
        if (shuffle == null) return;
        if (shuffle.nextToContribute().toString() != this.currentAccount!.accountAddress.toString()) return;
        const contribution = shuffle.generateContribution();
        const conHex = contribution.toHex();
        console.log(`contribution: ${conHex}`);
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${CONTRACT_ADDRESS}::poker_room::process_shuffle_contribution`,
                typeArguments: [],
                functionArguments: [
                    this.roomAddress!,
                    deckgenIdx,
                    contribution.toBytes(),
                ]
            }
        });

        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount!,
            transaction: txn
        });

        const committedTxn = await this.client.transaction.submit.simple({
            transaction: txn,
            senderAuthenticator: signedTxn
        });
        
        const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        if (txnResponse.success) {
            console.log(`Contributed to deckgen ${deckgenIdx}.`);
        } else {
            console.error(`Failed to contribute to deckgen ${deckgenIdx}: ${txnResponse.vm_status}`);
        }

    }

    private async performDKGActions() {
        const dkgSession = this.tableBrief!.curDKGSession;
        if (dkgSession == null) return;
        const dkgIdx = this.tableBrief!.numDKGsDone;

        if (dkgSession.state != STATE_IN_PROGRESS) {
            console.log(`DKG ${dkgIdx} is not in progress.`);
            return;
        }

        const myIdx = dkgSession.expectedContributors.findIndex(addr => addr.toString() == this.currentAccount!.accountAddress.toString());
        if (myIdx == -1) {
            console.log(`DKG ${dkgIdx} does not need my contribution.`);
            return;
        }

        if (dkgSession.contributions[myIdx] != null) {
            const contributionBytes = dkgSession.contributions[myIdx].toBytes();
            const contributionHash = bytesToHex(sha3_256(contributionBytes));
            const secretShare = localStorage.getItem(`rooms/${this.roomAddress!}/dkgs/${dkgIdx}/contributionHash/${contributionHash}/secretShare`);
            if (secretShare == null) {
                throw new Error(`I lost my secret share for DKG ${dkgIdx}!`);
            }
            console.log(`DKG ${dkgIdx} already has a contribution from me.`);
            return;
        }

        const { secretShare, contribution } = dkgSession.generateContribution();
        const contributionBytes = contribution.toBytes();
        const contributionHash = bytesToHex(sha3_256(contributionBytes));
        localStorage.setItem(`rooms/${this.roomAddress!}/dkgs/${dkgIdx}/contributionHash/${contributionHash}/secretShare`, secretShare.toHex());

        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${CONTRACT_ADDRESS}::poker_room::process_dkg_contribution`,
                typeArguments: [],
                functionArguments: [
                    this.roomAddress!,
                    dkgIdx,
                    contribution.toBytes(),
                ]
            }
        });
        
        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount!,
            transaction: txn
        });

        const committedTxn = await this.client.transaction.submit.simple({
            transaction: txn,
            senderAuthenticator: signedTxn
        });
        
        const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
        if (txnResponse.success) {
            console.log(`Contributed to DKG ${dkgIdx}.`);
        } else {
            console.error(`Failed to contribute to DKG ${dkgIdx}: ${txnResponse.vm_status}`);
        }
    }
}

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new GameApp();
});
