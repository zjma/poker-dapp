import { Account, AccountAddress, EntryFunctionArgumentTypes, SimpleEntryFunctionArgumentTypes } from "@aptos-labs/ts-sdk";
import * as ThresholdScalarMul from './crypto/threshold_scalar_mul';
import * as DKG from './crypto/dkg_v0';
import * as Reencryption from './crypto/reencryption';
import * as Shuffle from './crypto/shuffle';
import * as PokerRoom from './poker_room';
export const PKG_0_ADDRESS = '0x378e6cca3f73cf78e7ec8046b91f6402b547678fe3eda777a21acfc4b77449eb';
export const PKG_1_ADDRESS = '0x6b3331e6edc0f34641c39aaaf1a03bcb22b5f8bf76bdf7eca8ab7778bfd62f63';

export function truncatedAddr(addr: string): string {
    return addr.slice(0, 4) + '...' + addr.slice(-4);
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a);
    result.set(b, a.length);
    return result;
}

export interface ContractFuncCall {
    functionName(): `${string}::${string}::${string}`;
    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes>;
}

export function normalizeAddress(address: string): string {
    // Remove '0x' prefix if present
    let cleanAddr = address.toLowerCase().replace('0x', '');
    
    // Pad with zeros to make it 64 characters (32 bytes)
    cleanAddr = cleanAddr.padStart(64, '0');
    
    // Add '0x' prefix back
    return `0x${cleanAddr}`;
}

export function isValidAddress(address: string): boolean {
    // Accept any hex string and normalize it
    return /^(0x)?[0-9a-fA-F]+$/.test(address);
}

export class StateUpdateTask implements ContractFuncCall {
    roomAddr: AccountAddress;

    constructor(roomAddr: AccountAddress) {
        this.roomAddr = roomAddr;
    }    
    functionName(): `${string}::${string}::${string}` {
        return `${PKG_1_ADDRESS}::poker_room::state_update`;
    }
    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.roomAddr];
    }
}

export class ThreshholdScalarMulTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    contribution: ThresholdScalarMul.VerifiableContribution;

    constructor(sessionAddr: AccountAddress, payload: ThresholdScalarMul.VerifiableContribution) {
        this.sessionAddr = sessionAddr;
        this.contribution = payload;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_0_ADDRESS}::threshold_scalar_mul::process_contribution`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.contribution.toBytes()];
    }
}

export class DKGTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    contribution: DKG.VerifiableContribution;

    constructor(sessionAddr: AccountAddress, payload: DKG.VerifiableContribution) {
        this.sessionAddr = sessionAddr;
        this.contribution = payload;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_0_ADDRESS}::dkg_v0::process_contribution`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.contribution.toBytes()];
    }
}

export class ReencTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    reencryption: Reencryption.VerifiableReencryption;

    constructor(sessionAddr: AccountAddress, payload: Reencryption.VerifiableReencryption) {
        this.sessionAddr = sessionAddr;
        this.reencryption = payload;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_0_ADDRESS}::reencryption::process_reencryption`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.reencryption.toBytes()];
    }
}

export class ShuffleTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    contribution: Shuffle.VerifiableContribution;

    constructor(sessionAddr: AccountAddress, payload: Shuffle.VerifiableContribution) {
        this.sessionAddr = sessionAddr;
        this.contribution = payload;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_0_ADDRESS}::shuffle::process_contribution`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.contribution.toBytes()];
    }
}

export class BetTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    newBet: number;

    constructor(sessionAddr: AccountAddress, newBet: number) {
        this.sessionAddr = sessionAddr;
        this.newBet = newBet;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_1_ADDRESS}::hand::process_bet_action`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.newBet];
    }
}

export class ShowdownTxn implements ContractFuncCall {
    sessionAddr: AccountAddress;
    dealingIdx: number;
    privateState: Reencryption.RecipientPrivateState;

    constructor(sessionAddr: AccountAddress, dealingIdx: number, privateState: Reencryption.RecipientPrivateState) {
        this.sessionAddr = sessionAddr;
        this.dealingIdx = dealingIdx;
        this.privateState = privateState;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_1_ADDRESS}::hand::process_showdown_reveal`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.sessionAddr, this.dealingIdx, this.privateState.toBytes()];
    }
}

export class CreateRoomTxn implements ContractFuncCall {
    seed: Uint8Array;
    allowedAddresses: AccountAddress[];

    constructor(seed: Uint8Array, allowedAddresses: AccountAddress[]) {
        this.seed = seed;
        this.allowedAddresses = allowedAddresses;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_1_ADDRESS}::poker_room::create`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.seed, this.allowedAddresses];
    }
}

export class JoinRoomTxn implements ContractFuncCall {
    roomAddr: AccountAddress;

    constructor(roomAddr: AccountAddress) {
        this.roomAddr = roomAddr;
    }

    functionName(): `${string}::${string}::${string}` {
        return `${PKG_1_ADDRESS}::poker_room::join`;
    }

    functionArguments(): Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes> {
        return [this.roomAddr];
    }
}

export class NewAccountPersisted {
    account: Account;

    constructor(account: Account) {
        this.account = account;
    }
}

export class NewAccountToPersist {
    account: Account;

    constructor(account: Account) {
        this.account = account;
    }
}

export class SavedSessionChecked {
    account: Account | null;
    roomAddr: AccountAddress | null;

    constructor(account: Account | null, roomAddr: AccountAddress | null) {
        this.account = account;
        this.roomAddr = roomAddr;
    }
}

export class NewRoomAddrToPersist {
    roomAddr: AccountAddress;

    constructor(roomAddr: AccountAddress) {
        this.roomAddr = roomAddr;
    }
}

export class SavedAccount {
    address: string;
    privateKeyHex: string;
    publicKeyHex: string;

    constructor(address: string, privateKeyHex: string, publicKeyHex: string) {
        this.address = address;
        this.privateKeyHex = privateKeyHex;
        this.publicKeyHex = publicKeyHex;
    }
}

export class NewAccountState {
    account: Account;
    balanceInOctas: number;

    constructor(account: Account, balanceInOctas: number) {
        this.account = account;
        this.balanceInOctas = balanceInOctas;
    }
}

export class NewRoomState {
    roomBrief: PokerRoom.SessionBrief;

    constructor(roomBrief: PokerRoom.SessionBrief) {
        this.roomBrief = roomBrief;
    }
}

export class RoomCreated {
    roomAddr: AccountAddress;

    constructor(roomAddr: AccountAddress) {
        this.roomAddr = roomAddr;
    }
}

export class Mutex {
    private _locked: boolean = false;
    private _waiting: (() => void)[] = [];
  
    async lock(): Promise<() => void> {
        const unlock = () => {
            const next = this._waiting.shift();
            if (next) {
            next();
            } else {
            this._locked = false;
            }
        };
    
        if (this._locked) {
            await new Promise<void>((resolve) => this._waiting.push(resolve));
        } else {
            this._locked = true;
        }
    
        return unlock;
    }
}
