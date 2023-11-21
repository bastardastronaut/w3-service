export type Listener<K> = (ev: K) => boolean | void | Promise<boolean | void>;
declare abstract class EventEmitter<EventMap> {
    listeners: {
        [K in keyof EventMap]: Set<Listener<EventMap[K]>>;
    };
    protected emit<K extends keyof EventMap>(type: K, ev: EventMap[K]): void;
    addEventListener<K extends keyof EventMap>(type: K, listener: Listener<EventMap[K]>): void;
    removeEventListener<K extends keyof EventMap>(type: K, listener: Listener<EventMap[K]>): void;
    removeAllListeners(): void;
}
export default EventEmitter;
