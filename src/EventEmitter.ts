export type Listener<K> = (ev: K) => boolean | void | Promise<boolean | void>; // <-- indicates whether to unsubscribe after first emit

let emitPer5Seconds = 0;
let eventTypes = new Map<string, number>();

setInterval(() => {
  if (emitPer5Seconds > 150) {
    console.log(
      `unaccaptable amount of events in the last 3 seconds: ${emitPer5Seconds}`
    );

    for (const [type, n] of Array.from(eventTypes.entries())) {
      console.log(type, n);
    }
  }
  eventTypes.clear();
  emitPer5Seconds = 0;
}, 3000);

abstract class EventEmitter<EventMap> {
  listeners: { [K in keyof EventMap]: Set<Listener<EventMap[K]>> } = {} as {
    [K in keyof EventMap]: Set<Listener<EventMap[K]>>;
  };

  protected emit<K extends keyof EventMap>(type: K, ev: EventMap[K]) {
    if (this.listeners[type])
      this.listeners[type].forEach((l) => {
        emitPer5Seconds++;

        eventTypes.set(type as string, (eventTypes.get(type as any) || 0) + 1);

        // TODO: potentially breaking change!
        // listeners now need to be synchronous and should not return a value, unless they want to unsubscribe
        const result = l(ev);
        if (result && !(result as Promise<boolean>).then) {
          this.listeners[type].delete(l);
        }
      });
  }

  addEventListener<K extends keyof EventMap>(
    type: K,
    listener: Listener<EventMap[K]>
  ): void {
    if (!this.listeners[type]) {
      this.listeners[type] = new Set();
    }
    this.listeners[type].add(listener);
  }

  removeEventListener<K extends keyof EventMap>(
    type: K,
    listener: Listener<EventMap[K]>
  ): void {
    this.listeners[type].delete(listener);
  }

  removeAllListeners() {
    for (let k in this.listeners) {
      this.listeners[k].clear();
    }
  }
}

export default EventEmitter;
