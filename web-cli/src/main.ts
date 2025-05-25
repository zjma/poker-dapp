import './styles.css';
import { Aptos, AptosConfig, Network, Account, AccountAddress, Ed25519PrivateKey, Deserializer, ClientConfig } from "@aptos-labs/ts-sdk";
import { hexToBytes } from '@noble/hashes/utils';
import { STATE_IN_PROGRESS } from './crypto/dkg_v0';
import * as Hand from './hand';
import * as Reencryption from './crypto/reencryption';
import * as ThresholdScalarMul from './crypto/threshold_scalar_mul';
import * as DKG from './crypto/dkg_v0';
import * as Shuffle from './crypto/shuffle';
import * as PokerRoom from './poker_room';
import * as Deckgen from './deck_gen';

// Global constants
const clientConfig: ClientConfig = {
    API_KEY: "AG-KRVJDJCRBKS4EPVR6KSCJADPGAY5DECY3"
};

const config = new AptosConfig({ network: Network.DEVNET, clientConfig });
const aptos = new Aptos(config);
const PKG_0_ADDRESS = '0xd209996a76fa1370bce1ff037bbe7ba3eefccd83ef1a9fddc53372367b3c4ed3';
const PKG_1_ADDRESS = '0x1ac4b9b5a15a252eb1568b46dc64961528ec98824624f54a5154bb31e2356ad7';

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
    private tableBrief: PokerRoom.SessionBrief | null;
    private client: Aptos;
    private tablePolling: any | null;
    private roomAddressLabel: any | null;
    private myBetAmount: HTMLInputElement | null;
    private allowedBetAmounts: number[] = [0, 100];
    private betBtn: HTMLButtonElement | null;
    private foldBtn: HTMLButtonElement | null;
    private autoRefresh: boolean = false;
    private loadingSpinner: HTMLElement | null = null;
    private mySitBtn: HTMLButtonElement | null;
    private lastActionContext: string = '';
    private leaveBtn: HTMLButtonElement | null;

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
        this.leaveBtn = document.getElementById('leave-btn') as HTMLButtonElement;
        this.leaveBtn!.addEventListener('click', () => this.handleLeaveBtn());
        
        this.betBtn = document.getElementById('my-bet-btn') as HTMLButtonElement;
        this.betBtn!.addEventListener('click', () => this.handleBetBtn());
        this.foldBtn = document.getElementById('my-fold-btn') as HTMLButtonElement;
        this.foldBtn!.addEventListener('click', () => this.handleFoldBtn());
        this.myBetAmount = document.getElementById('my-bet-amount') as HTMLInputElement;
        this.myBetAmount!.addEventListener('input', () => this.handleMyBetAmountChange(parseInt(this.myBetAmount!.value)));
        
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
    private async handleLeaveBtn() {
        this.autoRefresh = false;
        this.tableView!.style.display = 'none';
        this.lobbyView!.style.display = 'flex';
    }
    async handleFoldBtn() {
        const curHand = this.tableBrief!.curHand!;
        console.log(curHand.addr.toString());
        console.log(curHand.secretInfo.toHex());
        const myPlayerIdx = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error('fold button should not be clickable when it is not your turn');
        }
        await this.submitNewBet(curHand, 0);
    }

    async handleBetBtn() {
        const newPost = parseInt(this.myBetAmount!.value);
        const curHand = this.tableBrief!.curHand!;
        const myPlayerIdx = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error('bet button should not be clickable when it is not your turn');
        }
        await this.submitNewBet(curHand, curHand.bets[myPlayerIdx] + newPost);
    }

    private async submitNewBet(hand: Hand.SessionBrief, newBet: number) {
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${PKG_1_ADDRESS}::hand::process_bet_action`,
                typeArguments: [],
                functionArguments: [hand.addr, newBet]
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
            console.log(`new bet for hand ${hand.addr.toString()}: ${newBet}`);
        } else {
            console.error(`error submitting bet transaction for hand ${hand.addr.toString()}: ${txnResponse.vm_status}`);
        }
    }

    private async handleMySit() {
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${PKG_1_ADDRESS}::poker_room::join`,
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
                function: `${PKG_1_ADDRESS}::poker_room::state_update`,
                typeArguments: [],
                functionArguments: [this.roomAddress!]
            }
        });
        
        const signedTxn = this.client.transaction.sign({
            signer: this.currentAccount!,
            transaction: txn
        });

        try {
            const committedTxn = await this.client.transaction.submit.simple({
                transaction: txn,
                senderAuthenticator: signedTxn
            });

            // Wait for transaction
            const txnResponse = await this.client.waitForTransaction({ transactionHash: committedTxn.hash });
            if (!txnResponse.success) {
                alert('Error submitting state update transaction: ' + txnResponse.vm_status);
                return;
            } else {
                console.log('State updated.');
            }

            // Fetch the latest room status
            const roomBrief = await this.fetchRoomStatus();

            // Update UI
            this.tableBrief = roomBrief;
            this.updateTableViews(roomBrief);
            this.loadingSpinner!.style.display = 'none';

            // Schedule next task
            await this.performCurHandBackgroundActions(roomBrief.curHand);
            await this.performDKGActions(roomBrief.curDKGSession);
            await this.performDeckgenActions(roomBrief.curDeckgenSession);
        } catch (e) {
            console.error(`Error refreshing room status: ${e}`);
        } finally {
            if (this.autoRefresh) {
                setTimeout(async () => {
                    await this.refreshRoomStatus();
                }, 3000);
            }    
        }
    }
    
    private async performCurHandBackgroundActions(curHand: Hand.SessionBrief | null) {
        if (!curHand) return;
        const myPlayerIdx = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error(`hand ${curHand.addr.toString()} does not have my account as a player`);
        }
        if (curHand.state == Hand.STATE__DEALING_PRIVATE_CARDS) {
            for (let i = 0; i < curHand.privateDealingSessions.length; i++) {
                console.log(`Hand ${curHand.addr.toString()} has a private dealing ${curHand.privateDealingSessions[i].addr.toString()} to work on.`);
                await this.tryContributeToPrivateDealing(curHand.privateDealingSessions[i]);
            }
        } else if (curHand.state == Hand.STATE__OPENING_COMMUNITY_CARDS) {
            for (let i = 0; i < curHand.publicOpeningSessions.length; i++) {
                console.log(`Hand ${curHand.addr.toString()} has a public opening ${curHand.publicOpeningSessions[i].addr.toString()} to work on.`);
                await this.tryContributeToScalarMul(curHand.publicOpeningSessions[i]);
            }
        } else if (curHand.state == Hand.STATE__SHOWDOWN) {
            for (let i = 0; i < 2; i++) {
                if (Hand.CARD__UNREVEALED != curHand.revealedPrivateCards[myPlayerIdx*2+i]) {
                    continue;
                } else {
                    const privateStateHex = localStorage.getItem(`reencs/${curHand.privateDealingSessions[myPlayerIdx*2+i].addr.toString()}/recipientPrivateState`)!;
                    const privateState = Reencryption.RecipientPrivateState.fromHex(privateStateHex);
                    const txn = await this.client.transaction.build.simple({
                        sender: this.currentAccount!.accountAddress,
                        data: {
                            function: `${PKG_1_ADDRESS}::hand::process_showdown_reveal`,
                            typeArguments: [],
                            functionArguments: [curHand.addr, myPlayerIdx*2+i, privateState.toBytes()],
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
                        console.log(`Successfully revealed private card ${myPlayerIdx*2+i} for hand ${curHand.addr.toString()}`);
                    } else {
                        console.error(`Error revealing private card ${myPlayerIdx*2+i} for hand ${curHand.addr.toString()}: ${txnResponse.vm_status}`);
                    }
                }
            }
        }
    }
    
    private async tryContributeToPrivateDealing(session: Reencryption.SessionBrief) {
        if (session.state == Reencryption.STATE__ACCEPTING_REENC && session.dealTarget.toString() == this.currentAccount!.accountAddress.toString()) {
            const {recipientPrivateState, verifiableReencryption} = session.reencrypt();
            localStorage.setItem(`reencs/${session.addr.toString()}/recipientPrivateState`, recipientPrivateState.toHex());
            const txn = await this.client.transaction.build.simple({
                sender: this.currentAccount!.accountAddress,
                data: {
                    function: `${PKG_0_ADDRESS}::reencryption::process_reencryption`,
                    typeArguments: [],
                    functionArguments: [session.addr, verifiableReencryption.toBytes()]
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
                console.log(`Successfully reencrypted for private dealing ${session.addr.toString()}`);
            } else {
                console.error(`Error reencrypting for private dealing ${session.addr.toString()}: ${txnResponse.vm_status}`);
            }
        } else if (session.state == Reencryption.STATE__THRESHOLD_SCALAR_MUL_IN_PROGRESS) {
            console.log(`Dealing ${session.addr.toString()} has a threshold scalar mul ${session.threshScalarMulSession!.addr.toString()} to work on.`);
            await this.tryContributeToScalarMul(session.threshScalarMulSession!);
        } else {
            console.log(`nothing to do for private dealing ${session.addr.toString()}`);
        }
    }

    private async tryContributeToScalarMul(session: ThresholdScalarMul.SessionBrief) {
        const secretShareHex = localStorage.getItem(`dkgs/${session.secretInfo.sessionAddr.toString()}/secretShare`)!;
        const secretShare = DKG.SecretShare.fromHex(secretShareHex);
        const myPlayerIdx = session.allowedContributors.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error('current account is not a contributor to this public opening');
        }
        if (session.state == ThresholdScalarMul.STATE__ACCEPTING_CONTRIBUTION_BEFORE_DEADLINE && !session.contributedFlags[myPlayerIdx]) {
            const contribution = session.generateContribution(this.currentAccount!.accountAddress, secretShare);
            const txn = await this.client.transaction.build.simple({
                sender: this.currentAccount!.accountAddress,
                data: {
                    function: `${PKG_0_ADDRESS}::threshold_scalar_mul::process_contribution`,
                    typeArguments: [],
                    functionArguments: [session.addr, contribution.toBytes()]
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
                console.log(`Successfully contributed to threshold scalar mul ${session.addr.toString()}`);
            } else {
                console.error(`Error contributing to threshold scalar mul ${session.addr.toString()}: ${txnResponse.vm_status}`);
            }
        } else {
            console.log(`nothing to do for threshold scalar mul ${session.addr.toString()}`);
        }
    }

    private handleMyBetAmountChange(targetAmount: number): any {
        const maxPossibleBet = Math.max(...this.allowedBetAmounts);
        const minPossibleBet = Math.min(...this.allowedBetAmounts);
        const closestValue = this.allowedBetAmounts.reduce((prev: number, curr: number) => {
            return (Math.abs(curr - targetAmount) < Math.abs(prev - targetAmount) ? curr : prev);
        });
        this.myBetAmount!.value = closestValue.toString();
        this.betBtn!.textContent = closestValue == maxPossibleBet ? 'ALL IN' : minPossibleBet == 0 && closestValue == 0 ? 'CHECK' : minPossibleBet == 0 && closestValue > 0 ? `BET ${closestValue}` : minPossibleBet > 0 && closestValue == minPossibleBet ? `CALL ${closestValue}` : `RAISE ${closestValue}`;
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
                function: `${PKG_1_ADDRESS}::poker_room::create`,
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
            (e: any) => e.type === `${PKG_1_ADDRESS}::poker_room::RoomCreatedEvent`
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

    private async fetchRoomStatus(): Promise<PokerRoom.SessionBrief> {
        const result = await this.client.view({
            payload: {
                function: `${PKG_1_ADDRESS}::poker_room::brief_bcs`,
                typeArguments: [],
                functionArguments: [this.roomAddress!]
            }
        });
        const hex = result[0] as string;
        const deserializer = new Deserializer(hexToBytes(hex.startsWith('0x') ? hex.slice(2) : hex));
        const brief = PokerRoom.SessionBrief.decode(deserializer);
        console.log(brief);
        return brief;
    }

    private updateTableViews(roomBrief: PokerRoom.SessionBrief) {
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
                continue;
            }
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
            document.getElementById(`${viewPrefix}-chips-in-hand`)!.textContent = '🪙 ' + (roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS ? roomBrief.curHand!.chipsInHand[playerIdx] : roomBrief.playerChips[playerIdx]);
            document.getElementById(`${viewPrefix}-dealer-light`)!.style.display = roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS && roomBrief.curHand!.players[0].toString() == curPlayerAddr.toString()? 'block' : 'none';
            document.getElementById(`${viewPrefix}-bet`)!.textContent = roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS ? roomBrief.curHand!.bets[playerIdx].toString() : '';
            let privateCardsArea = document.getElementById(`${viewPrefix}-private-cards-area`);
            if (roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS && roomBrief.curHand!.state != Hand.STATE__DEALING_PRIVATE_CARDS) {
                privateCardsArea!.style.display = 'block';
                for (let privateCardIdx = 0; privateCardIdx < 2; privateCardIdx++) {
                    const card = roomBrief.curHand!.revealedPrivateCards[playerIdx*2+privateCardIdx];
                    this.updateCardSlot(`${viewPrefix}-card-${privateCardIdx}`, card == Hand.CARD__UNREVEALED ? null : card);
                }
                document.getElementById(`${viewPrefix}-fold-flag`)!.style.display = roomBrief.curHand!.foldStatuses[playerIdx] ? 'flex' : 'none';
                console.log(`Rival ${rivalNumber} has private cards: ${roomBrief.curHand!.revealedPrivateCards[playerIdx*2]} ${roomBrief.curHand!.revealedPrivateCards[playerIdx*2+1]}`);
            } else {
                privateCardsArea!.style.display = 'none';
            }

            if (rivalNumber == 0) {
                // Self view
                if (roomBrief.state != PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS || roomBrief.curHand!.state == Hand.STATE__DEALING_PRIVATE_CARDS) {
                    this.updateCardSlot('my-card-0', null);
                    this.updateCardSlot('my-card-1', null);
                    document.getElementById('my-fold-flag')!.style.display = 'none';
                } else {
                    const myDealing0PriSt = Reencryption.RecipientPrivateState.fromHex(localStorage.getItem(`reencs/${roomBrief.curHand!.privateDealingSessions[myPlayerIdx*2]!.addr.toString()}/recipientPrivateState`)!);
                    const myDealing1PriSt = Reencryption.RecipientPrivateState.fromHex(localStorage.getItem(`reencs/${roomBrief.curHand!.privateDealingSessions[myPlayerIdx*2+1]!.addr.toString()}/recipientPrivateState`)!);
                    const myCard0Repr = roomBrief.curHand!.privateDealingSessions[myPlayerIdx*2]!.reveal(myDealing0PriSt);
                    const myCard1Repr = roomBrief.curHand!.privateDealingSessions[myPlayerIdx*2+1]!.reveal(myDealing1PriSt);
                    const myCard0 = roomBrief.curHand!.cardReprs.findIndex(cardRepr => cardRepr.toHex() == myCard0Repr.toHex());
                    const myCard1 = roomBrief.curHand!.cardReprs.findIndex(cardRepr => cardRepr.toHex() == myCard1Repr.toHex());
                    if (myCard0 == -1 || myCard1 == -1) {
                        throw new Error('Card not found');
                    }
                    this.updateCardSlot('my-card-0', myCard0);
                    this.updateCardSlot('my-card-1', myCard1);
                    document.getElementById('my-fold-flag')!.style.display = this.tableBrief!.curHand!.foldStatuses[myPlayerIdx] ? 'flex' : 'none';
                }
                const betControls = document.getElementById(`${viewPrefix}-bet-decision-inputs`);
                if (roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS && roomBrief.curHand!.state == Hand.STATE__PLAYER_BETTING && roomBrief.curHand!.currentActionPlayerIdx == myPlayerIdx) {
                    betControls!.style.display = 'block';
                    const amountInput = document.getElementById(`${viewPrefix}-bet-amount`) as HTMLInputElement;
                    const maxBetOnTable = roomBrief.curHand!.bets.reduce((max: number, bet: number) => Math.max(max, bet), 0);
                    const myBet = roomBrief.curHand!.bets[playerIdx];
                    const myChipsInHand = roomBrief.curHand!.chipsInHand[playerIdx];
                    const minToAdd = Math.min(maxBetOnTable - myBet, myChipsInHand);
                    amountInput!.min = minToAdd.toString();
                    amountInput!.max = myChipsInHand.toString();
                    const minRaiseStep = roomBrief.curHand!.minRaiseStep;
                    this.allowedBetAmounts = Array.from({length: myChipsInHand - minToAdd + 1}, (_, i) => minToAdd + i).filter((amount) => amount == minToAdd || amount == myChipsInHand || amount >= minToAdd + minRaiseStep);
                    let currentActionContext = roomBrief.curHand!.toHex();
                    if (currentActionContext != this.lastActionContext) {
                        this.lastActionContext = currentActionContext;
                        this.handleMyBetAmountChange(minToAdd);
                    }
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
        const inHandPublicInfo = document.getElementById('in-hand-public-info')!;
        const dkgOrShuffleInProgressFlag = document.getElementById('dkg-or-shuffle-in-progress-flag')!;
        const finalizedFlag = document.getElementById('finalized-flag')!;
        const waitingForPlayersFlag = document.getElementById('waiting-for-players-flag')!;
        inHandPublicInfo.style.display = 'none';
        dkgOrShuffleInProgressFlag.style.display = 'none';
        finalizedFlag.style.display = 'none';
        waitingForPlayersFlag.style.display = 'none';
        
        if (roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS) {
            inHandPublicInfo!.style.display = 'flex';
            document.getElementById('total-in-pot-value')!.textContent = roomBrief.curHand!.bets.reduce((sum: number, bet: number) => sum + bet, 0).toString();
            for (let i = 0; i < 5; i++) {
                this.updateCardSlot(`community-card-${i}`, roomBrief.curHand!.publiclyOpenedCards[i] ?? null);
            }
        } else if (roomBrief.state == PokerRoom.STATE__WAITING_FOR_PLAYERS) {
            waitingForPlayersFlag.style.display = 'flex';
        } else if (roomBrief.state == PokerRoom.STATE__CLOSED) {
            finalizedFlag.style.display = 'flex';
        } else {
            dkgOrShuffleInProgressFlag.style.display = 'flex';
        }
        
    }

    private updateCardSlot(htmlId: string, cardIdx: number | null) {
        const cardHolder = document.getElementById(htmlId)!;
        cardHolder.classList.remove('red-suit');
        cardHolder.classList.remove('card-back');
        cardHolder.classList.remove('card');
        cardHolder.textContent = '';
        if (cardIdx == null) {
            cardHolder.classList.add('card-back');
        } else {
            cardHolder.classList.add('card');
            const cardText = this.cardTextFromCardIdx(cardIdx);
            cardHolder.textContent = cardText;
            if (cardText[1] == '♥' || cardText[1] == '♦') {
                cardHolder!.classList.add('red-suit');
            }
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
                        function: `${PKG_1_ADDRESS}::poker_room::about`,
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
        localStorage.setItem('LAST_ROOM', this.roomAddress!);
        // Update views.
        this.setDisplayNoneForAllGameContentVariants();
        this.loadingSpinner!.style.display = 'block';
        this.roomAddressLabel!.textContent = `${this.roomAddress!}`;
        this.fetchRoomStatus().then((roomBrief) => {
            this.tableBrief = roomBrief;
            this.updateTableViews(roomBrief);
            this.setDisplayNoneForAllGameContentVariants();
            this.tableView!.style.display = 'block';
        });
        this.autoRefresh = true;
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
                    function: `${PKG_1_ADDRESS}::poker_room::join`,
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

    private async performDeckgenActions(deckgenSession: Deckgen.SessionBrief | null) {
        if (deckgenSession == null) return;
        const shuffle = deckgenSession.shuffle;
        if (shuffle.status != Shuffle.STATE__ACCEPTING_CONTRIBUTION) return;
        if (shuffle.nextToContribute().toString() != this.currentAccount!.accountAddress.toString()) return;
        console.time('generateContribution');
        const contribution = shuffle.generateContribution();
        console.timeEnd('generateContribution');
        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${PKG_0_ADDRESS}::shuffle::process_contribution`,
                typeArguments: [],
                functionArguments: [
                    shuffle.addr,
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
            console.log(`Contributed to deckgen ${deckgenSession.addr.toString()}.`);
        } else {
            console.error(`Failed to contribute to deckgen ${deckgenSession.addr.toString()}: ${txnResponse.vm_status}`);
        }

    }

    private async performDKGActions(dkgSession: DKG.SessionBrief | null) {
        if (dkgSession == null) return;

        if (dkgSession.state != STATE_IN_PROGRESS) {
            console.log(`DKG ${dkgSession.addr.toString()} is not in progress.`);
            return;
        }

        const myIdx = dkgSession.expectedContributors.findIndex(addr => addr.toString() == this.currentAccount!.accountAddress.toString());
        if (myIdx == -1) {
            console.log(`DKG ${dkgSession.addr.toString()} does not need my contribution.`);
            return;
        }

        if (dkgSession.contributionFlags[myIdx]) {
            const secretShareHex = localStorage.getItem(`dkgs/${dkgSession.addr.toString()}/secretShare`);
            if (secretShareHex == null) {
                throw new Error(`I lost my secret share for DKG ${dkgSession.addr.toString()}!`);
            }
            console.log(`DKG ${dkgSession.addr.toString()} already has a contribution from me.`);
            return;
        }

        const { secretShare, contribution } = dkgSession.generateContribution();
        localStorage.setItem(`dkgs/${dkgSession.addr.toString()}/secretShare`, secretShare.toHex());

        const txn = await this.client.transaction.build.simple({
            sender: this.currentAccount!.accountAddress,
            data: {
                function: `${PKG_0_ADDRESS}::dkg_v0::process_contribution`,
                typeArguments: [],
                functionArguments: [
                    dkgSession.addr,
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
            console.log(`Contributed to DKG ${dkgSession.addr.toString()}.`);
        } else {
            console.error(`Failed to contribute to DKG ${dkgSession.addr.toString()}: ${txnResponse.vm_status}`);
        }
    }
}

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new GameApp();
});
