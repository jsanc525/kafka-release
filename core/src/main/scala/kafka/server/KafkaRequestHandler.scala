/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kafka.server

import java.util
import java.util.Objects
import java.util.concurrent._
import java.util.concurrent.atomic.AtomicInteger

import com.github.benmanes.caffeine.cache._
import com.yammer.metrics.core.Meter
import kafka.metrics.KafkaMetricsGroup
import kafka.network._
import kafka.utils._
import org.apache.kafka.common.TopicPartition
import org.apache.kafka.common.internals.FatalExitError
import org.apache.kafka.common.utils.{KafkaThread, Time}

import scala.collection.{JavaConverters, mutable}

/**
 * A thread that answers kafka requests.
 */
class KafkaRequestHandler(id: Int,
                          brokerId: Int,
                          val aggregateIdleMeter: Meter,
                          val totalHandlerThreads: AtomicInteger,
                          val requestChannel: RequestChannel,
                          apis: KafkaApis,
                          time: Time) extends Runnable with Logging {
  this.logIdent = "[Kafka Request Handler " + id + " on Broker " + brokerId + "], "
  private val shutdownComplete = new CountDownLatch(1)
  @volatile private var stopped = false

  def run() {
    while (!stopped) {
      // We use a single meter for aggregate idle percentage for the thread pool.
      // Since meter is calculated as total_recorded_value / time_window and
      // time_window is independent of the number of threads, each recorded idle
      // time should be discounted by # threads.
      val startSelectTime = time.nanoseconds

      val req = requestChannel.receiveRequest(300)
      val endTime = time.nanoseconds
      val idleTime = endTime - startSelectTime
      aggregateIdleMeter.mark(idleTime / totalHandlerThreads.get)

      req match {
        case RequestChannel.ShutdownRequest =>
          debug(s"Kafka request handler $id on broker $brokerId received shut down command")
          shutdownComplete.countDown()
          return

        case request: RequestChannel.Request =>
          try {
            request.requestDequeueTimeNanos = endTime
            trace(s"Kafka request handler $id on broker $brokerId handling request $request")
            apis.handle(request)
          } catch {
            case e: FatalExitError =>
              shutdownComplete.countDown()
              Exit.exit(e.statusCode)
            case e: Throwable => error("Exception when handling request", e)
          } finally {
            request.releaseBuffer()
          }

        case null => // continue
      }
    }
    shutdownComplete.countDown()
  }

  def stop(): Unit = {
    stopped = true
  }

  def initiateShutdown(): Unit = requestChannel.sendShutdownRequest()

  def awaitShutdown(): Unit = shutdownComplete.await()

}

class KafkaRequestHandlerPool(val brokerId: Int,
                              val requestChannel: RequestChannel,
                              val apis: KafkaApis,
                              time: Time,
                              numThreads: Int,
                              requestHandlerAvgIdleMetricName: String,
                              logAndThreadNamePrefix : String) extends Logging with KafkaMetricsGroup {

  private val threadPoolSize: AtomicInteger = new AtomicInteger(numThreads)
  /* a meter to track the average free capacity of the request handlers */
  private val aggregateIdleMeter = newMeter(requestHandlerAvgIdleMetricName, "percent", TimeUnit.NANOSECONDS)

  this.logIdent = "[" + logAndThreadNamePrefix + " Kafka Request Handler on Broker " + brokerId + "], "
  val runnables = new mutable.ArrayBuffer[KafkaRequestHandler](numThreads)
  for (i <- 0 until numThreads) {
    createHandler(i)
  }

  def createHandler(id: Int): Unit = synchronized {
    runnables += new KafkaRequestHandler(id, brokerId, aggregateIdleMeter, threadPoolSize, requestChannel, apis, time)
    KafkaThread.daemon(logAndThreadNamePrefix + "-kafka-request-handler-" + id, runnables(id)).start()
  }

  def resizeThreadPool(newSize: Int): Unit = synchronized {
    val currentSize = threadPoolSize.get
    info(s"Resizing request handler thread pool size from $currentSize to $newSize")
    if (newSize > currentSize) {
      for (i <- currentSize until newSize) {
        createHandler(i)
      }
    } else if (newSize < currentSize) {
      for (i <- 1 to (currentSize - newSize)) {
        runnables.remove(currentSize - i).stop()
      }
    }
    threadPoolSize.set(newSize)
  }

  def shutdown(): Unit = synchronized {
    info("shutting down")
    for (handler <- runnables)
      handler.initiateShutdown()
    for (handler <- runnables)
      handler.awaitShutdown()
    info("shut down completely")
  }
}

class BrokerTopicMetrics(topicName: Option[String], partition: Option[String] = None) extends KafkaMetricsGroup {
  val tags: scala.collection.Map[String, String] = topicName match {
    case None => Map.empty
    case Some(topic) => {
    if(partition.isEmpty) Map("topic" -> topic)
    else Map("topic" -> topic, "partition" -> partition.get)
    }
  }

  val messagesInRate = newMeter(BrokerTopicStats.MessagesInPerSec, "messages", TimeUnit.SECONDS, tags)
  val bytesInRate = newMeter(BrokerTopicStats.BytesInPerSec, "bytes", TimeUnit.SECONDS, tags)
  val bytesOutRate = newMeter(BrokerTopicStats.BytesOutPerSec, "bytes", TimeUnit.SECONDS, tags)
  val bytesRejectedRate = newMeter(BrokerTopicStats.BytesRejectedPerSec, "bytes", TimeUnit.SECONDS, tags)
  private[server] val replicationBytesInRate =
    if (topicName.isEmpty) Some(newMeter(BrokerTopicStats.ReplicationBytesInPerSec, "bytes", TimeUnit.SECONDS, tags))
    else None
  private[server] val replicationBytesOutRate =
    if (topicName.isEmpty) Some(newMeter(BrokerTopicStats.ReplicationBytesOutPerSec, "bytes", TimeUnit.SECONDS, tags))
    else None
  val failedProduceRequestRate = newMeter(BrokerTopicStats.FailedProduceRequestsPerSec, "requests", TimeUnit.SECONDS, tags)
  val failedFetchRequestRate = newMeter(BrokerTopicStats.FailedFetchRequestsPerSec, "requests", TimeUnit.SECONDS, tags)
  val totalProduceRequestRate = newMeter(BrokerTopicStats.TotalProduceRequestsPerSec, "requests", TimeUnit.SECONDS, tags)
  val totalFetchRequestRate = newMeter(BrokerTopicStats.TotalFetchRequestsPerSec, "requests", TimeUnit.SECONDS, tags)
  val fetchMessageConversionsRate = newMeter(BrokerTopicStats.FetchMessageConversionsPerSec, "requests", TimeUnit.SECONDS, tags)
  val produceMessageConversionsRate = newMeter(BrokerTopicStats.ProduceMessageConversionsPerSec, "requests", TimeUnit.SECONDS, tags)

  def close() {
    removeMetric(BrokerTopicStats.MessagesInPerSec, tags)
    removeMetric(BrokerTopicStats.BytesInPerSec, tags)
    removeMetric(BrokerTopicStats.BytesOutPerSec, tags)
    removeMetric(BrokerTopicStats.BytesRejectedPerSec, tags)
    if (replicationBytesInRate.isDefined)
      removeMetric(BrokerTopicStats.ReplicationBytesInPerSec, tags)
    if (replicationBytesOutRate.isDefined)
      removeMetric(BrokerTopicStats.ReplicationBytesOutPerSec, tags)
    removeMetric(BrokerTopicStats.FailedProduceRequestsPerSec, tags)
    removeMetric(BrokerTopicStats.FailedFetchRequestsPerSec, tags)
    removeMetric(BrokerTopicStats.TotalProduceRequestsPerSec, tags)
    removeMetric(BrokerTopicStats.TotalFetchRequestsPerSec, tags)
    removeMetric(BrokerTopicStats.FetchMessageConversionsPerSec, tags)
    removeMetric(BrokerTopicStats.ProduceMessageConversionsPerSec, tags)
  }
}

object BrokerTopicStats {
  val MessagesInPerSec = "MessagesInPerSec"
  val BytesInPerSec = "BytesInPerSec"
  val BytesOutPerSec = "BytesOutPerSec"
  val BytesRejectedPerSec = "BytesRejectedPerSec"
  val ReplicationBytesInPerSec = "ReplicationBytesInPerSec"
  val ReplicationBytesOutPerSec = "ReplicationBytesOutPerSec"
  val FailedProduceRequestsPerSec = "FailedProduceRequestsPerSec"
  val FailedFetchRequestsPerSec = "FailedFetchRequestsPerSec"
  val TotalProduceRequestsPerSec = "TotalProduceRequestsPerSec"
  val TotalFetchRequestsPerSec = "TotalFetchRequestsPerSec"
  val FetchMessageConversionsPerSec = "FetchMessageConversionsPerSec"
  val ProduceMessageConversionsPerSec = "ProduceMessageConversionsPerSec"
  private val valueFactory = (k: String) => new BrokerTopicMetrics(Some(k))
  private val topicPartitionValueFactory = (k: (String, Integer)) => new BrokerTopicMetrics(Some(k._1), Some(k._2.toString))
}

class ProducerStats(producerCacheMaxSize: Int, producerCacheExpiryMs: Long) extends Logging {
  Objects.requireNonNull(producerCacheMaxSize, "producerCacheMaxSize can not be null")
  Objects.requireNonNull(producerCacheExpiryMs, "producerCacheExpiryMs can not be null")

  private val factory = (k: (String, TopicPartition)) => new BrokerClientMetrics(k._1, k._2)
  private val clientMetrics = new Pool[(String, TopicPartition), BrokerClientMetrics](Some(factory))
  
  private val removalListener = new RemovalListener[String, util.Collection[TopicPartition]] {
    override def onRemoval(key: String, value: util.Collection[TopicPartition], cause: RemovalCause): Unit = {
      debug(s"Cache removal listener invoked for key: $key and value as $value")
      removeMetrics(key, value)
    }
  }

  private val cacheLoader = new CacheLoader[String, util.Collection[TopicPartition]]() {
    override def load(key: String): util.Collection[TopicPartition] = ConcurrentHashMap.newKeySet()
  }

  private val clientTopicPartitions: LoadingCache[String, util.Collection[TopicPartition]] = Caffeine.newBuilder()
    .expireAfterWrite(producerCacheExpiryMs, TimeUnit.MILLISECONDS)
    .expireAfterAccess(producerCacheExpiryMs, TimeUnit.MILLISECONDS)
    .maximumSize(producerCacheMaxSize)
    .initialCapacity(producerCacheMaxSize/2)
    .removalListener(removalListener)
    .build(cacheLoader)

  // clears cache every 5 mins as caffeine cache does not guarantee to remove entries as soon as expired.
  // This gives deterministic behavior about producers considered to be inactive as those metrics are removed.
  Executors.newScheduledThreadPool(1, new ThreadFactory {
    override def newThread(r: Runnable): Thread = {
      val thread = Executors.defaultThreadFactory().newThread(r)
      thread.setName("client-topic-metrics-cache-cleanup-thread")
      thread.setDaemon(true)
      thread
    }
  }).scheduleWithFixedDelay(new Runnable {
    override def run(): Unit = {
      clientTopicPartitions.cleanUp()
    }
  }, 5, 300, TimeUnit.SECONDS)

  def clientMetrics(clientId:String, topicPartition: TopicPartition): BrokerClientMetrics = {
    Objects.requireNonNull(topicPartition, "topicPartition can not be null")
    val topicPartitions = clientTopicPartitions.get(clientId)
    if(topicPartitions != null) topicPartitions.add(topicPartition)
    // setting the value as get may invalidate before returning the value.
    clientTopicPartitions.put(clientId, topicPartitions)

    clientMetrics.getAndMaybePut(Tuple2(clientId, topicPartition))
  }

  def removeMetrics(clientId: String) {
    val partitions: util.Collection[TopicPartition] = clientTopicPartitions.getIfPresent(clientId)
    removeMetrics(clientId, partitions)
  }

  private def removeMetrics(clientId: String, partitions: util.Collection[TopicPartition]) = {
    debug(s"Removing clientId: $clientId with partitions: $partitions")
    if (partitions != null && !partitions.isEmpty) {
      JavaConverters.collectionAsScalaIterable(partitions).foreach(tp => {
        val metrics = clientMetrics.remove((clientId, tp))
        if (metrics != null) metrics.close()
      })
    }
  }

  def close(): Unit = {
    clientMetrics.values.foreach(_.close())
  }
}

class BrokerClientMetrics(clientId:String, topicPartition: TopicPartition) extends Logging with KafkaMetricsGroup {
  val tags: scala.collection.Map[String, String] =
    Map("clientId"-> clientId, "topic" -> topicPartition.topic, "partition" -> topicPartition.partition.toString)

  val messagesInRate = newMeter(BrokerTopicStats.MessagesInPerSec, "messages", TimeUnit.SECONDS, tags)

  def close(): Unit = {
    removeMetric(BrokerTopicStats.MessagesInPerSec, tags)
    debug(s"Removing client metrics $tags")
  }

}

class BrokerTopicStats {
  import BrokerTopicStats._

  private val topicStats = new Pool[String, BrokerTopicMetrics](Some(valueFactory))
  private val topicPartitionStats = new Pool[(String, Integer), BrokerTopicMetrics](Some(topicPartitionValueFactory))
  val allTopicsStats = new BrokerTopicMetrics(None)

  def topicStats(topic: String, partition: Integer = null): BrokerTopicMetrics = {
    if(partition != null)
      topicPartitionStats.getAndMaybePut((topic, partition))
    else
      topicStats.getAndMaybePut(topic)
  }

  def updateReplicationBytesIn(value: Long) {
    allTopicsStats.replicationBytesInRate.foreach { metric =>
      metric.mark(value)
    }
  }

  private def updateReplicationBytesOut(value: Long) {
    allTopicsStats.replicationBytesOutRate.foreach { metric =>
      metric.mark(value)
    }
  }

  def removeMetrics(topic: String) {
    val metrics = topicStats.remove(topic)
    if (metrics != null)
      metrics.close()
  }

  def removeMetrics(topicPartition: TopicPartition) {
    val partitionMetrics = topicPartitionStats.remove(Tuple2(topicPartition.topic, topicPartition.partition))
    if(partitionMetrics != null) partitionMetrics.close()
  }

  def updateBytesOut(topicPartition: TopicPartition, isFollower: Boolean, value: Long) {
    if (isFollower) {
      updateReplicationBytesOut(value)
    } else {
      topicStats(topicPartition.topic()).bytesOutRate.mark(value)
      topicStats(topicPartition.topic(), topicPartition.partition).bytesOutRate.mark(value)
      allTopicsStats.bytesOutRate.mark(value)
    }
  }


  def close(): Unit = {
    allTopicsStats.close()
    topicStats.values.foreach(_.close())
  }

}
