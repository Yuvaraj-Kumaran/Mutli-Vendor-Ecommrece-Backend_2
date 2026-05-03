import Redis from 'ioredis';

export const redis = new Redis({
  host: process.env.REDIS_HOST || "127.0.0.1",
  port: Number(process.env.REDIS_PORT) || 6379,
  maxRetriesPerRequest: 1,
  retryStrategy: () => null,
});

redis.on("connect", () => {
  console.log("Local Redis connected");
});

redis.on("error", (err) => {
  console.error("Redis error:", err.message);
});


export default redis;