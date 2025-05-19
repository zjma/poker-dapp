import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Element } from "./group";

export class Context {
    basePoint: Element;
    publicPoint: Element;

    constructor(basePoint: Element, publicPoint: Element) {
        this.basePoint = basePoint;
        this.publicPoint = publicPoint;
    }

    static decode(deserializer: Deserializer): Context {
        const basePoint = Element.decode(deserializer);
        const publicPoint = Element.decode(deserializer);
        return new Context(basePoint, publicPoint);
    }

    encode(serializer: Serializer): void {
        this.basePoint.encode(serializer);
        this.publicPoint.encode(serializer);
    }
}
