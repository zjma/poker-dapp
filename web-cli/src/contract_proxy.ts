import { Aptos, AptosConfig, Network, ClientConfig, Account, AccountAddress, Deserializer, EntryFunctionArgumentTypes, SimpleEntryFunctionArgumentTypes } from "@aptos-labs/ts-sdk";
import { Mutex, PKG_0_ADDRESS, PKG_1_ADDRESS } from './utils';
import * as PokerRoom from './poker_room';
import { hexToBytes } from '@noble/hashes/utils';
import * as Reencryption from './crypto/reencryption';
import * as ThresholdScalarMul from './crypto/threshold_scalar_mul';
import * as DKG from './crypto/dkg_v0';
import * as Shuffle from './crypto/shuffle';


const clientConfig: ClientConfig = {
    API_KEY: "AG-KRVJDJCRBKS4EPVR6KSCJADPGAY5DECY3"
};
const config = new AptosConfig({ network: Network.DEVNET, clientConfig });
const aptos = new Aptos(config);

let currentAccount: Account | null = null;


export function setAccount(account: Account) {
    currentAccount = account;
}

const txnMutex = new Mutex();

async function runTxnSynchronized(func: `${string}::${string}::${string}`, functionArguments: Array<EntryFunctionArgumentTypes | SimpleEntryFunctionArgumentTypes>): Promise<string> {
    const unlock = await txnMutex.lock();
    const txn = await aptos.transaction.build.simple({
        sender: currentAccount!.accountAddress,
        data: {
            function: func,
            typeArguments: [],
            functionArguments
        }
    });

    try {
        const signedTxn = aptos.transaction.sign({
            signer: currentAccount!,
            transaction: txn
        });
    
        const committedTxn = await aptos.transaction.submit.simple({
            transaction: txn,
            senderAuthenticator: signedTxn
        });
        await aptos.waitForTransaction({ transactionHash: committedTxn.hash });
    
        return committedTxn.hash;
    } finally {
        unlock();
    }
}

export async function createRoom(seed: Uint8Array, allowedAddresses: AccountAddress[]): Promise<AccountAddress> {

    const txnHash = await runTxnSynchronized(`${PKG_1_ADDRESS}::poker_room::create`, [seed, allowedAddresses]);
    const txnDetails = await aptos.getTransactionByHash({ transactionHash: txnHash });
    const events = (txnDetails as any).events || [];
    const roomCreatedEvent = events.find(
        (e: any) => e.type === `${PKG_1_ADDRESS}::poker_room::RoomCreatedEvent`
    );
    
    if (!roomCreatedEvent) {
        throw new Error('Room creation event not found');
    }

    return roomCreatedEvent.data.room_addr;
}

export async function fetchBalance(accountAddress: AccountAddress): Promise<number> {
    const balance = await aptos.getAccountAPTAmount({
        accountAddress: accountAddress
    });
    return Number(balance);
}

export async function fetchContractMetadata(): Promise<string> {
    const result = await aptos.view({
        payload: {
            function: `${PKG_1_ADDRESS}::poker_room::about`,
            typeArguments: [],
            functionArguments: []
        }
    });
    const version = result[0]?.toString() ?? 'unknown';
    return version;
}

export async function triggerRoomStateTransition(roomAddr: AccountAddress) {
    await runTxnSynchronized(`${PKG_1_ADDRESS}::poker_room::state_update`, [roomAddr]);
}

export async function fetchRoomStatus(roomAddr: AccountAddress): Promise<PokerRoom.SessionBrief> {
    const result = await aptos.view({
        payload: {
            function: `${PKG_1_ADDRESS}::poker_room::brief_bcs`,
            typeArguments: [],
            functionArguments: [roomAddr]
        }
    });
    const hex = result[0] as string;
    const deserializer = new Deserializer(hexToBytes(hex.startsWith('0x') ? hex.slice(2) : hex));
    const brief = PokerRoom.SessionBrief.decode(deserializer);
    console.log(brief);
    return brief;
}

export async function submitNewBet(handAddr: AccountAddress, amount: number) {
    await runTxnSynchronized(`${PKG_1_ADDRESS}::hand::process_bet_action`, [handAddr, amount]);
}

export async function joinRoom(roomAddr: AccountAddress) {
    await runTxnSynchronized(`${PKG_1_ADDRESS}::poker_room::join`, [roomAddr]);
}

export async function revealPrivateCard(handAddr: AccountAddress, cardIdx: number, privateState: Reencryption.RecipientPrivateState) {
    await runTxnSynchronized(`${PKG_1_ADDRESS}::hand::process_showdown_reveal`, [handAddr, cardIdx, privateState.toBytes()]);
}

export async function submitReencryption(sessionAddr: AccountAddress, verifiableReencryption: Reencryption.VerifiableReencryption) {
    await runTxnSynchronized(`${PKG_0_ADDRESS}::reencryption::process_reencryption`, [sessionAddr, verifiableReencryption.toBytes()]);
}

export async function submitThresholdScalarMulContribution(sessionAddr: AccountAddress, contribution: ThresholdScalarMul.VerifiableContribution) {
    await runTxnSynchronized(`${PKG_0_ADDRESS}::threshold_scalar_mul::process_contribution`, [sessionAddr, contribution.toBytes()]);
}

export async function submitDKGContribution(sessionAddr: AccountAddress, contribution: DKG.VerifiableContribution) {
    await runTxnSynchronized(`${PKG_0_ADDRESS}::dkg_v0::process_contribution`, [sessionAddr, contribution.toBytes()]);
}

export async function submitShuffleContribution(shuffleAddr: AccountAddress, contribution: Shuffle.VerifiableContribution) {
    await runTxnSynchronized(`${PKG_0_ADDRESS}::shuffle::process_contribution`, [shuffleAddr, contribution.toBytes()]);
}