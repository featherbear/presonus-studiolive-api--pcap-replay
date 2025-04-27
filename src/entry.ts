import pcap from "pcap";

import fs from "node:fs";
import { Address4 } from "ip-address";

const file = process.argv[2];

import bunyan from "bunyan";

const logger = bunyan.createLogger({
  name: "pcap-parser",
  level: "warn",
});
logger.debug("WOW");

if (!file) {
  console.error("Please provide a file path");
  process.exit(1);
}
if (!fs.existsSync(file)) {
  console.error(`File ${file} does not exist`);
  process.exit(1);
}

if (!process.argv[3]) {
  console.error("Please provide a console IP");
  process.exit(1);
}
const consoleIP = new Address4(process.argv[3]).toArray();

logger.info("Loaded PCAP file", file);

import StudioLiveAPI, {
  MessageCode,
} from "../../presonus-studiolive-api/src/api";
import DataClient from "../../presonus-studiolive-api/src/lib/util/DataClient";
const api = new StudioLiveAPI({ host: consoleIP });

import { Socket } from "node:net";
import Queue from "queue";
import chalk from "chalk";

class Mocket extends Socket {
  connect() {
    // We don't actually connect
    setTimeout(() => {
      // Emulate connect event
      this.emit("connect");
    }, 500);
    return this;
  }

  write(buffer: string | Uint8Array, cb?: (err?: Error) => void): boolean;
  write(
    str: string | Uint8Array,
    encoding?: BufferEncoding,
    cb?: (err?: Error) => void
  ): boolean;
  write(buffer: any, encodingOrCb?: any, cb?: any): boolean {
    logger.debug({ buffer }, "Dropping write action");
    return true;
  }

  inject(data: Buffer) {
    this.emit("data", data);
  }
}

const socket = new Mocket();

// Library has no types
let EthernetPacket = require("pcap/decode/ethernet_packet.js");
let IPv4 = require("pcap/decode/ipv4.js");
let TCP = require("pcap/decode/tcp.js");

function eq<T>(a: T[], b: T[]) {
  return a.length === b.length && a.every((v, i) => b[i] === v);
}

// Override the DataClient to use our mocked Socket object
api["conn"] = DataClient(api["handleRecvPacket"].bind(api), socket);

async function wait(ms: number) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(true);
    }, ms);
  });
}

// Queue
const sendBufferQueue: any[] = [];

async function main() {
  // Initiate connection, the API will use the mocked socket
  api.connect();

  // Give a little time for the mocked connection to be established
  await wait(1800);

  // Emulate the console returning the keep alive request
  setInterval(() => {
    api["keepAliveHelper"].updateTime();
  }, 2000);

  // api.on(MessageCode.ParamValue, d => {
  //   console.log(chalk.red(JSON.stringify(d)));
  // })

  api.on(MessageCode.FaderPosition, (d) => {
    console.log(chalk.green(JSON.stringify(d)));
  });

  // Packet sending queue
  const Q = new Queue({ autostart: true, concurrency: 1 });
  pcap
    .createOfflineSession(file, {
      filter: "ip and tcp and port 53000",
    })
    .on("packet", (rawPacket) => {
      const decoded = pcap.decode.packet(rawPacket);

      if (!(decoded.payload instanceof EthernetPacket)) return;
      const ethPacket = decoded.payload;

      if (!(ethPacket.payload instanceof IPv4)) return;
      const IPv4Packet = ethPacket.payload;

      if (!(ethPacket.payload.payload instanceof TCP)) return;
      const tcpPacket = IPv4Packet.payload;

      // From console
      if (eq(IPv4Packet.saddr.addr, consoleIP)) {
        if (!tcpPacket.data) return;

        sendBufferQueue.push(Buffer.from(tcpPacket.data));

        Q.push((n) => {
          setTimeout(() => {
            const data = sendBufferQueue.shift();
            socket.inject(data);
            if (n) n();
          }, 20);
        });
      } else if (eq(IPv4Packet.daddr.addr, consoleIP)) {
        // To console
        return;
      } else {
        // Not from/to console
        return;
      }
    });
}

main();
