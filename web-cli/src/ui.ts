import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as PokerRoom from './poker_room';
import * as Hand from './hand';
import * as Reencryption from './crypto/reencryption';
import * as ThresholdScalarMul from './crypto/threshold_scalar_mul';
import * as ContractProxy from './contract_proxy';
import * as DKG from './crypto/dkg_v0';
import * as Deckgen from './deck_gen';
import * as Shuffle from './crypto/shuffle';
import * as Utils from './utils';

export class UIManager {
    private savedAccount: Utils.SavedAccount | null = null;
    private savedRoomAddr: AccountAddress | null = null;

    private loginDialog: HTMLElement | null;
    private newAccountBtn: HTMLElement | null;
    private savedAccountBtn: HTMLElement | null;
    private currentAccount: Account | null = null;
    private createRoomBtn: HTMLButtonElement | null;
    private findRoomBtn: HTMLButtonElement | null;
    private lobbyView: HTMLElement | null;
    private roomView: HTMLElement | null;
    private hostDialog: HTMLElement | null;
    private contractStatusLabel: HTMLElement | null;
    private curAccountLabel: HTMLElement | null;
    private balanceLabel: HTMLElement | null;
    private startGameBtn: HTMLButtonElement | null;
    private cancelHostBtn: HTMLButtonElement | null;
    private allowedAddressesInput: HTMLTextAreaElement | null;
    private roomAddress: AccountAddress | null = null;
    private roomBrief: PokerRoom.SessionBrief | null;
    private roomAddressLabel: any | null;
    private handAddrLabel: HTMLElement | null;
    private myBetAmount: HTMLInputElement | null;
    private allowedBetAmounts: number[] = [0, 100];
    private betBtn: HTMLButtonElement | null;
    private foldBtn: HTMLButtonElement | null;
    private loadingSpinner: HTMLElement | null = null;

    private lastActionContext: string = '';


    constructor() {

        this.roomBrief = null;
        this.contractStatusLabel = document.getElementById('contract-status');
        this.curAccountLabel = document.getElementById('cur-account-status');
        this.roomAddressLabel = document.getElementById('room-addr-label');
        this.handAddrLabel = document.getElementById('hand-addr-label');
        this.balanceLabel = document.getElementById('balance-status');
        this.loginDialog = document.getElementById('login-dialog');
        this.newAccountBtn = document.getElementById('new-account-btn');
        this.newAccountBtn!.addEventListener('click', () => this.handleNewAccount());
        this.savedAccountBtn = document.getElementById('saved-account-btn');
        this.savedAccountBtn!.addEventListener('click', () => this.handleSavedAccountClick());
        this.createRoomBtn = document.getElementById('create-room-btn') as HTMLButtonElement;
        this.createRoomBtn!.addEventListener('click', () => this.showCreateRoomDialog());
        this.findRoomBtn = document.getElementById('find-room-btn') as HTMLButtonElement;
        this.findRoomBtn!.addEventListener('click', () => this.handleFindRoom());
        this.lobbyView = document.getElementById('lobby-view');
        this.roomView = document.getElementById('room-view');
        this.hostDialog = document.getElementById('host-dialog');
        this.startGameBtn = document.getElementById('start-game-btn') as HTMLButtonElement;
        this.startGameBtn!.addEventListener('click', () => this.handleCreateRoom());
        this.cancelHostBtn = document.getElementById('cancel-host-btn') as HTMLButtonElement;
        this.cancelHostBtn!.addEventListener('click', () => this.hideHostDialog());
        this.allowedAddressesInput = document.getElementById('allowed-addresses') as HTMLTextAreaElement;
        
        this.betBtn = document.getElementById('my-bet-btn') as HTMLButtonElement;
        this.betBtn!.addEventListener('click', () => this.handleBetBtn());
        this.foldBtn = document.getElementById('my-fold-btn') as HTMLButtonElement;
        this.foldBtn!.addEventListener('click', () => this.handleFoldBtn());
        this.myBetAmount = document.getElementById('my-bet-amount') as HTMLInputElement;
        this.myBetAmount!.addEventListener('input', () => this.handleMyBetAmountChange(parseInt(this.myBetAmount!.value)));
        
        this.loadingSpinner = document.getElementById('loading-spinner');

        document.getElementById('room-addr-label')!.addEventListener('click', () => this.onRoomInfoClick());
        document.getElementById('close-room-info-dialog')!.addEventListener('click', () => this.onCloseRoomInfoDialog());
        document.getElementById('copy-room-addr-btn')!.addEventListener('click', () => this.onCopyRoomAddrBtnClick());
        document.getElementById('room-in-explorer-btn')!.addEventListener('click', () => this.onRoomInExplorerBtnClick());
        
        document.getElementById('hand-addr-label')!.addEventListener('click', () => this.onHandInfoClick());
        document.getElementById('close-hand-info-dialog')!.addEventListener('click', () => this.onCloseHandInfoDialog());
        document.getElementById('hand-in-explorer-btn')!.addEventListener('click', () => this.onHandInExplorerBtnClick());
        
        document.getElementById('faucet-btn')!.addEventListener('click', () => this.onFaucetBtnClick());
        document.getElementById('shortcut-to-lobby')!.addEventListener('click', () => this.handleLeaveRoom());
        document.getElementById('you-can-join-link')!.addEventListener('click', () => this.onSitBtnClick());
        
        this.startContractPingLoop();
        this.initializeToLoginDialog();
    }

    onHandInExplorerBtnClick(): any {
        const url = `https://explorer.aptoslabs.com/object/${this.roomBrief!.curHand!.addr_self.toString()}/resources?network=devnet`;
        window.open(url, '_blank');
    }

    onCloseHandInfoDialog(): any {
        document.getElementById('hand-info-dialog')!.style.display = 'none';
    }

    onRoomInExplorerBtnClick(): any {
        const url = `https://explorer.aptoslabs.com/object/${this.roomAddress!.toString()}/resources?network=devnet`;
        window.open(url, '_blank');
    }

    onHandInfoClick(): any {
        document.getElementById('hand-info-dialog')!.style.display = 'flex';
    }


    private onCopyRoomAddrBtnClick(): any {
        if (this.roomAddress) {
            navigator.clipboard.writeText(this.roomAddress.toString());
        }
    }

    private onRoomInfoClick() {
        document.getElementById('room-info-dialog')!.style.display = 'flex';
    }

    private onCloseRoomInfoDialog() {
        document.getElementById('room-info-dialog')!.style.display = 'none';
    }

    private handleLeaveRoom() {
        this.roomAddress = null;
        this.roomBrief = null;
        this.setDisplayNoneForAllGameContentVariants();
        this.lobbyView!.style.display = 'flex';
    }

    private disableBetControls() {
        this.betBtn!.disabled = true;
        this.foldBtn!.disabled = true;
        this.myBetAmount!.disabled = true;
    }

    private enableBetControls() {
        this.betBtn!.disabled = false;
        this.foldBtn!.disabled = false;
        this.myBetAmount!.disabled = false;
    }

    async handleFoldBtn() {
        const curHand = this.roomBrief!.curHand!;
        const myPlayerIdx = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error('fold button should not be clickable when it is not your turn');
        }
        this.disableBetControls();
        await ContractProxy.submitNewBet(curHand.addr_self, 0);
    }

    async handleBetBtn() {
        const newPost = parseInt(this.myBetAmount!.value);
        const curHand = this.roomBrief!.curHand!;
        const myPlayerIdx = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdx == -1) {
            throw new Error('bet button should not be clickable when it is not your turn');
        }
        this.disableBetControls();
        await ContractProxy.submitNewBet(curHand.addr_self, curHand.bets[myPlayerIdx] + newPost);
    }

    private async onSitBtnClick() {
        await ContractProxy.joinRoom(this.roomAddress!);
    }
    
    private async performCurHandBackgroundActions(curHand: Hand.SessionBrief | null) {
        if (!curHand) return;
        const myPlayerIdxInHand = curHand.players.findIndex((player: AccountAddress) => player.toString() == this.currentAccount!.accountAddress.toString());
        if (myPlayerIdxInHand == -1) {
            console.log(`hand ${curHand.addr_self.toString()} does not need me.`);
            return;
        }
        if (curHand.state == Hand.STATE__DEALING_PRIVATE_CARDS) {
            for (let i = 0; i < curHand.privateDealingSessions.length; i++) {
                console.log(`Hand ${curHand.addr_self.toString()} has a private dealing ${curHand.privateDealingSessions[i].addr.toString()} to work on.`);
                await this.tryContributeToPrivateDealing(curHand.privateDealingSessions[i]);
            }
        } else if (curHand.state == Hand.STATE__OPENING_COMMUNITY_CARDS) {
            for (let i = 0; i < curHand.publicOpeningSessions.length; i++) {
                console.log(`Hand ${curHand.addr_self.toString()} has a public opening ${curHand.publicOpeningSessions[i].addr.toString()} to work on.`);
                await this.tryContributeToScalarMul(curHand.publicOpeningSessions[i]);
            }
        } else if (curHand.state == Hand.STATE__SHOWDOWN) {
            for (let i = 0; i < 2; i++) {
                if (Hand.CARD__UNREVEALED != curHand.revealedPrivateCards[myPlayerIdxInHand*2+i]) {
                    continue;
                } else {
                    const privateStateHex = localStorage.getItem(`reencs/${curHand.privateDealingSessions[myPlayerIdxInHand*2+i].addr.toString()}/recipientPrivateState`)!;
                    const privateState = Reencryption.RecipientPrivateState.fromHex(privateStateHex);
                    await ContractProxy.revealPrivateCard(curHand.addr_self, myPlayerIdxInHand*2+i, privateState);
                }
            }
        }
    }
    
    private async tryContributeToPrivateDealing(session: Reencryption.SessionBrief) {
        if (session.state == Reencryption.STATE__ACCEPTING_REENC && session.dealTarget.toString() == this.currentAccount!.accountAddress.toString()) {
            const {recipientPrivateState, verifiableReencryption} = session.reencrypt();
            localStorage.setItem(`reencs/${session.addr.toString()}/recipientPrivateState`, recipientPrivateState.toHex());

            console.log(`brief=${session.toHex()}`);
            console.log(`contr=${verifiableReencryption.toHex()}`);
            await ContractProxy.submitReencryption(session.addr, verifiableReencryption);
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
            await ContractProxy.submitThresholdScalarMulContribution(session.addr, contribution);
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

    private async handleSavedAccountClick() {
        const privateKeyHex = this.savedAccount!.privateKeyHex.replace('0x', '');
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
        ContractProxy.setAccount(this.currentAccount!);
        this.startBalancePolling();

        if (this.savedRoomAddr) {
            this.roomAddress = this.savedRoomAddr;
            this.onEnteringGameRoom();
        } else {
            this.onEnteringLobby();
        }
    }

    private onEnteringLobby() {
        this.setDisplayNoneForAllGameContentVariants();
        this.lobbyView!.style.display = 'flex'; 
    }

    private async startBalancePolling() {
        while (true) {
            try {
                const balanceInOctas = await ContractProxy.fetchBalance(this.currentAccount!.accountAddress);

                const balanceInAPT = Number(balanceInOctas) / 100000000;
                this.balanceLabel!.textContent = `Balance: ${balanceInAPT.toString()} APT`;
            } catch (error) {
                this.balanceLabel!.textContent = 'Balance: ERROR';
            }
            await new Promise(r => setTimeout(r, 3000));
        }
    }

    private showCreateRoomDialog() {
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

        this.roomAddress = await ContractProxy.createRoom(seed, addresses.map(addr => AccountAddress.fromString(addr)));

        this.hideHostDialog();
        this.onEnteringGameRoom();
    }

    private async handleFindRoom() {
        // Prompt for room address
        const roomAddress = prompt('Enter room address:');
        if (!roomAddress) return;

        // Normalize the address
        const normalizedAddress = this.normalizeAddress(roomAddress);
        if (!this.isValidAddress(normalizedAddress)) {
            alert('Invalid room address');
            return;
        }

        this.roomAddress = AccountAddress.fromString(normalizedAddress);
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

    private renderMyPhysicalStateBox(playerIdxInRoom: number) {
        let box = document.getElementById('my-physical-state')!;
        if (this.roomBrief!.curHand?.idxByAddr(this.currentAccount!.accountAddress) != null) {
            box.style.display = 'none';
        } else {
            box.style.display = 'flex';
            this.renderAwayLabel(0, playerIdxInRoom);
            this.renderJoinNowLink();
        }
    }

    private renderAwayLabel(seatIdx: number, playerIdxInRoom: number) {
        const viewPrefix = seatIdx == 0 ? 'my' : `rival-${seatIdx}`;
        const awayLabel = document.getElementById(`${viewPrefix}-away-flag`);
        const playerAddr = this.roomBrief!.expectedPlayerAddresses[playerIdxInRoom];
        if (this.roomBrief!.state == PokerRoom.STATE__WAITING_FOR_PLAYERS) {
            if (this.roomBrief!.playerLivenesses[playerIdxInRoom]) {
                awayLabel!.style.display = 'flex';
                awayLabel!.textContent = 'READY';
            } else {
                awayLabel!.style.display = 'flex';
                awayLabel!.textContent = 'AWAY';
                }
        } else if (this.roomBrief!.playerChips[playerIdxInRoom] == 0) {
            awayLabel!.style.display = 'flex';
            awayLabel!.textContent = 'Busted';
        } else if (!this.roomBrief!.playerLivenesses[playerIdxInRoom]) {
            awayLabel!.style.display = 'flex';
            awayLabel!.textContent = 'AWAY';
        } else if (this.roomBrief!.curHand?.idxByAddr(playerAddr) != null || this.roomBrief!.curDKGSession?.idxByAddr(playerAddr) != null || this.roomBrief!.curDeckgenSession?.idxByAddr(playerAddr) != null) {
            awayLabel!.style.display = 'none';
        } else {
            awayLabel!.style.display = 'flex';
            awayLabel!.textContent = 'Back in next hand';
        }
    }

    private renderLastActionLabel(seatIdx: number, playerAddr: AccountAddress) {
        const viewPrefix = seatIdx == 0 ? 'my' : `rival-${seatIdx}`;
        const lastActionLabel = document.getElementById(`${viewPrefix}-fold-flag`)!;
        const idxInHand = this.roomBrief!.curHand?.idxByAddr(playerAddr) ?? null;
        lastActionLabel.style.display = 'none';
        if (idxInHand == null) return;
        if (!this.roomBrief!.curHand!.hasActed(idxInHand)) {
            if (playerAddr.toString() == this.currentAccount!.accountAddress.toString()) return;
            if (this.roomBrief!.curHand!.expectingActionFrom != idxInHand) return;
        }

        lastActionLabel.style.display = 'flex';
        lastActionLabel.textContent = this.roomBrief!.curHand!.getLastActionText(idxInHand);
    }

    private updateRoomViews(roomBrief: PokerRoom.SessionBrief) {
        let shortRoomAddr = this.roomAddress!.toString().slice(0, 4) + '...' + this.roomAddress!.toString().slice(-4);
        this.roomAddressLabel!.textContent = `Room: ${shortRoomAddr}`;

        if (roomBrief.curHand == null) {
            this.handAddrLabel!.textContent = `Getting ready for hand #${roomBrief.numHandsDone + 1}...`;
        } else {
            this.handAddrLabel!.textContent = `Hand #${roomBrief.numHandsDone + 1}`;
        }

        // Determine which player to view as: if I'm one of the players, view as myself; otherwise, view as the first player in the room.
        var firstPersonIdxInRoom = roomBrief.expectedPlayerAddresses.findIndex(addr => addr.toString() == this.currentAccount!.accountAddress.toString());
        if (firstPersonIdxInRoom == -1) firstPersonIdxInRoom = 0;

        const numUiSeats = 8;
        const numPlayers = roomBrief.expectedPlayerAddresses.length;
        const viewIdxsByIdxInRoom = Array.from({length: numPlayers}, (_, playerIdx) => Math.round((playerIdx + numPlayers - firstPersonIdxInRoom) % numPlayers * numUiSeats / numPlayers));
        for (let seatIdx = 0; seatIdx < numUiSeats; seatIdx++) {
            const playerIdxInRoom = viewIdxsByIdxInRoom.findIndex(viewIdx => viewIdx == seatIdx);
            const viewPrefix = seatIdx == 0 ? 'my' : `rival-${seatIdx}`;
            const curBox = document.getElementById(`${viewPrefix}-box`);
            this.renderAwayLabel(seatIdx, playerIdxInRoom);

            if (playerIdxInRoom < 0) {
                // This seat is not used for the current tournament. Hide it.
                curBox!.style.display = 'none';
                continue;
            }

            const curPlayerAddr = roomBrief.expectedPlayerAddresses[playerIdxInRoom];
            // Try get the idx in the current hand.
            // NOTE: there may not be a current hand!
            // NOTE: the first-person player may not be in the current hand!
            let idxInHand = roomBrief.curHand?.idxByAddr(curPlayerAddr) ?? null;
            let idxInDKG = roomBrief.curDKGSession?.idxByAddr(curPlayerAddr) ?? null;
            let idxInDeckgen = roomBrief.curDeckgenSession?.idxByAddr(curPlayerAddr) ?? null;

            curBox!.style.display = 'flex';
            if (roomBrief.state == PokerRoom.STATE__WAITING_FOR_PLAYERS && roomBrief.playerLivenesses[playerIdxInRoom]
                || roomBrief.state == PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS && idxInHand != null
                || roomBrief.state == PokerRoom.STATE__DECKGEN_IN_PROGRESS && idxInDeckgen != null
                || roomBrief.state == PokerRoom.STATE__DKG_IN_PROGRESS && idxInDKG != null
            ) {
                curBox!.classList.remove('player-away');
                curBox!.classList.add('player-at-table');
            } else {
                curBox!.classList.remove('player-at-table');
                curBox!.classList.add('player-away');
            }
            
            document.getElementById(`${viewPrefix}-addr`)!.textContent = seatIdx == 0 ? "You" : curPlayerAddr.toString().slice(0, 4) + '...' + curPlayerAddr.toString().slice(-4);
            document.getElementById(`${viewPrefix}-chips-in-hand`)!.textContent = '🪙 ' + (idxInHand != null ? roomBrief.curHand!.chipsInHand[idxInHand] : roomBrief.playerChips[playerIdxInRoom]);
            document.getElementById(`${viewPrefix}-dealer-light`)!.style.display = roomBrief.curHand?.players[0].toString() == curPlayerAddr.toString() ? 'flex' : 'none';
            document.getElementById(`${viewPrefix}-bet`)!.textContent = idxInHand != null ? roomBrief.curHand!.bets[idxInHand].toString() : '';
            let privateCardsArea = document.getElementById(`${viewPrefix}-private-cards-area`);
            if (idxInHand != null && (seatIdx == 0 || (roomBrief.curHand!.state == Hand.STATE__SHOWDOWN || roomBrief.curHand!.state == Hand.STATE__SUCCEEDED) && roomBrief.curHand!.playerStates[idxInHand] != Hand.PLAYER_STATE__FOLDED)) {
                privateCardsArea!.style.display = 'block';
                for (let privateCardIdx = 0; privateCardIdx < 2; privateCardIdx++) {
                    const card = roomBrief.curHand!.revealedPrivateCards[idxInHand*2+privateCardIdx];
                    this.updateCardSlot(`${viewPrefix}-card-${privateCardIdx}`, card == Hand.CARD__UNREVEALED ? null : card);
                }
            } else {
                privateCardsArea!.style.display = 'none';
            }

            this.renderLastActionLabel(seatIdx, curPlayerAddr);

            if (seatIdx == 0) {
                // Self view
                if (roomBrief.state != PokerRoom.STATE__HAND_AND_NEXT_DECKGEN_IN_PROGRESS || roomBrief.curHand!.state == Hand.STATE__DEALING_PRIVATE_CARDS || idxInHand == null) {
                    this.updateCardSlot('my-card-0', null);
                    this.updateCardSlot('my-card-1', null);
                    document.getElementById('my-fold-flag')!.style.display = 'none';
                } else {
                    const myDealing0PriSt = Reencryption.RecipientPrivateState.fromHex(localStorage.getItem(`reencs/${roomBrief.curHand!.privateDealingSessions[idxInHand*2]!.addr.toString()}/recipientPrivateState`)!);
                    const myDealing1PriSt = Reencryption.RecipientPrivateState.fromHex(localStorage.getItem(`reencs/${roomBrief.curHand!.privateDealingSessions[idxInHand*2+1]!.addr.toString()}/recipientPrivateState`)!);
                    const myCard0Repr = roomBrief.curHand!.privateDealingSessions[idxInHand*2]!.reveal(myDealing0PriSt);
                    const myCard1Repr = roomBrief.curHand!.privateDealingSessions[idxInHand*2+1]!.reveal(myDealing1PriSt);
                    const myCard0 = roomBrief.curHand!.cardReprs.findIndex(cardRepr => cardRepr.toHex() == myCard0Repr.toHex());
                    const myCard1 = roomBrief.curHand!.cardReprs.findIndex(cardRepr => cardRepr.toHex() == myCard1Repr.toHex());
                    if (myCard0 == -1 || myCard1 == -1) {
                        throw new Error('Card not found');
                    }
                    this.updateCardSlot('my-card-0', myCard0);
                    this.updateCardSlot('my-card-1', myCard1);
                }
                const betControls = document.getElementById(`${viewPrefix}-bet-decision-inputs`);
                if (idxInHand != null &&roomBrief.curHand!.expectingActionFrom == idxInHand) {
                    betControls!.style.display = 'block';
                    const amountInput = document.getElementById(`${viewPrefix}-bet-amount`) as HTMLInputElement;
                    const maxBetOnTable = roomBrief.curHand!.bets.reduce((max: number, bet: number) => Math.max(max, bet), 0);
                    const myBet = roomBrief.curHand!.bets[idxInHand!];
                    const myChipsInHand = roomBrief.curHand!.chipsInHand[idxInHand!];
                    const minToAdd = Math.min(maxBetOnTable - myBet, myChipsInHand);
                    amountInput!.min = minToAdd.toString();
                    amountInput!.max = myChipsInHand.toString();
                    const minRaiseStep = roomBrief.curHand!.minRaiseStep();
                    this.allowedBetAmounts = Array.from({length: myChipsInHand - minToAdd + 1}, (_, i) => minToAdd + i).filter((amount) => amount == minToAdd || amount == myChipsInHand || amount >= minToAdd + minRaiseStep);
                    let currentActionContext = roomBrief.curHand!.toHex();
                    if (currentActionContext != this.lastActionContext) {
                        this.enableBetControls();
                        this.lastActionContext = currentActionContext;
                        this.handleMyBetAmountChange(minToAdd);
                    }
                } else {
                    betControls!.style.display = 'none';
                }
                this.renderMyPhysicalStateBox(playerIdxInRoom);
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
            if (roomBrief.hasCompetitor(this.currentAccount!.accountAddress)) {
            } else {
                waitingForPlayersFlag.style.display = 'flex';
            }
        } else if (roomBrief.state == PokerRoom.STATE__CLOSED) {
            finalizedFlag.style.display = 'flex';
        } else {
            dkgOrShuffleInProgressFlag.style.display = 'flex';
        }
        
    }

    private renderJoinNowLink() {
        const youCanJoinLink = document.getElementById('you-can-join-link')!;
        if (this.roomBrief!.canJoin(this.currentAccount!.accountAddress)) {
            youCanJoinLink.style.display = 'flex';
            if (this.roomBrief!.state == PokerRoom.STATE__WAITING_FOR_PLAYERS) {
                youCanJoinLink.textContent = "I'm ready.";
            } else {
                youCanJoinLink.textContent = "I'm ready for next hand.";
            }
        } else {
            youCanJoinLink.style.display = 'none';
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
                const version = await ContractProxy.fetchContractMetadata();
                this.contractStatusLabel!.textContent = 'contract: OK(' + version + ')';
            } catch (error) {
                this.contractStatusLabel!.textContent = 'contract: unhealthy!';
            }

            await new Promise(r => setTimeout(r, 10000));
        }
    }


    private async roomRefreshLoop() {
        while (this.roomAddress != null) {
            await ContractProxy.triggerRoomStateTransition(this.roomAddress!);
            if (this.roomAddress == null) break;
            const roomBrief = await ContractProxy.fetchRoomStatus(this.roomAddress!);
            if (this.roomAddress == null) break;
            this.roomBrief = roomBrief;
            this.updateRoomViews(roomBrief);
            await this.performCurHandBackgroundActions(roomBrief.curHand);
            await this.performDKGActions(roomBrief.curDKGSession);
            await this.performDeckgenActions(roomBrief.curDeckgenSession);
            await new Promise(r => setTimeout(r, 1000));
        }
    }

    private async onEnteringGameRoom() {
        localStorage.setItem('LAST_ROOM', this.roomAddress!.toString());
        this.setDisplayNoneForAllGameContentVariants();
        this.loadingSpinner!.style.display = 'block';
        this.roomAddressLabel!.textContent = `${this.roomAddress!}`;
        const roomBrief = await ContractProxy.fetchRoomStatus(this.roomAddress!);
        this.roomBrief = roomBrief;
        this.updateRoomViews(roomBrief);
        this.setDisplayNoneForAllGameContentVariants();
        this.roomView!.style.display = 'block';
        this.roomRefreshLoop();
    }

    private setDisplayNoneForAllGameContentVariants() {
        this.lobbyView!.style.display = 'none';
        this.roomView!.style.display = 'none';
        this.loadingSpinner!.style.display = 'none';
    }

    private async performDeckgenActions(deckgenSession: Deckgen.SessionBrief | null) {
        if (deckgenSession == null) return;
        const shuffle = deckgenSession.shuffle;
        if (shuffle.status != Shuffle.STATE__ACCEPTING_CONTRIBUTION) return;
        if (shuffle.nextToContribute().toString() != this.currentAccount!.accountAddress.toString()) return;
        console.time('generateContribution');
        const contribution = shuffle.generateContribution();
        await ContractProxy.submitShuffleContribution(shuffle.addr, contribution);
        console.timeEnd('generateContribution');
    }

    private async performDKGActions(dkgSession: DKG.SessionBrief | null) {
        if (dkgSession == null) return;

        if (dkgSession.state != DKG.STATE_IN_PROGRESS) {
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
        await ContractProxy.submitDKGContribution(dkgSession.addr, contribution);
    }

    private async onFaucetBtnClick() {
        if (this.currentAccount == null) {
            throw new Error("unreachable");
        }

        const address = this.currentAccount.accountAddress.toString();
        await fetch(`https://faucet.devnet.aptoslabs.com/mint?amount=100000000&address=${address}`, {
            method: 'POST'
        });
    }

    private hideAllGameContentChildren() {
        this.loginDialog!.style.display = 'none';
        this.lobbyView!.style.display = 'none';
        this.roomView!.style.display = 'none';
        this.loadingSpinner!.style.display = 'none';
    }

    private initializeToLoginDialog() {
        const savedAccountAsJson = localStorage.getItem('SAVED_ACCOUNT');
        this.savedAccount = savedAccountAsJson != null ? JSON.parse(savedAccountAsJson) : null;
        const lastRoomAddrStr = localStorage.getItem('LAST_ROOM');
        this.savedRoomAddr = lastRoomAddrStr != null ? AccountAddress.fromString(lastRoomAddrStr) : null;
    
        this.hideAllGameContentChildren();
        document.getElementById('login-dialog')!.style.display = 'flex';
        const savedAccountButton = document.getElementById('saved-account-btn')!;
        if (this.savedAccount == null) {
            savedAccountButton.style.display = 'none';
        } else {
            savedAccountButton.style.display = 'flex';
            const shortAccountAddr = this.savedAccount.address.slice(0, 4) + '...' + this.savedAccount.address.slice(-4);
            if (this.savedRoomAddr == null) {
                savedAccountButton.textContent = `Continue as account ${shortAccountAddr}`;
            } else {
                const shortRoomAddr = this.savedRoomAddr.toString().slice(0, 4) + '...' + this.savedRoomAddr.toString().slice(-4);
                savedAccountButton.textContent = `Continue as account ${shortAccountAddr} and return to room ${shortRoomAddr}`;
            }
        }
    }

    private async handleNewAccount() {
        // Generate new account
        const newAccount = Account.generate();
        
        // Save account data
        const accountData: Utils.SavedAccount = {
            address: newAccount.accountAddress.toString(),
            privateKeyHex: newAccount.privateKey.toString(),
            publicKeyHex: newAccount.publicKey.toString()
        };
        
        localStorage.setItem('SAVED_ACCOUNT', JSON.stringify(accountData));
        ContractProxy.setAccount(newAccount);

        this.currentAccount = newAccount;
        
        this.loginDialog!.style.display = 'none';
        this.curAccountLabel!.textContent = `Account: ${newAccount.accountAddress.toString()}`;
        this.balanceLabel!.textContent = `Balance: fetching...`;
        this.lobbyView!.style.display = 'flex';
        this.startBalancePolling();
    }
}
