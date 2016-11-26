package iredis;

import com.yahoo.ycsb.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Protocol;
import redis.clients.jedis.exceptions.JedisConnectionException;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static com.yahoo.ycsb.Status.ERROR;
import static com.yahoo.ycsb.Status.OK;

/**
 * IRedis client binding for YCSB.
 *
 * This is a proof-of-concept implementation of the ideas presented in
 * the "Crowdsourced Data Integrity Verification for  Key-Value Stores in the Cloud" paper.
 *
 *
 */
public class IRedisClient extends DB {

  private Jedis jedis;

  private static final String HOST_PROPERTY = "redis.host";
  private static final String PORT_PROPERTY = "redis.port";
  private static final String PASSWORD_PROPERTY = "redis.password";
  private static final String BULK_SIZE_PROPERTY = "i.bulk.size";
  private static final String P_PARAM_PROPERTY = "i.p.param";
  private static final String AUTH_KEY_PROPERTY = "i.auth.key";
  private static final String ENC_KEY_PROPERTY = "i.enc.key";
  private static final int VERIFICATION_QUERIES_POOL_SIZE = 10;

  private static final String LINK_DATA_LABEL = "Link-Data";
  private static final String LINK_DATA_DELIMITER = ",";
  private static final String MAC_LABEL = "MAC";
  private static final Random RAND = new Random();
  private static final Charset CHARSET = Charset.forName("UTF-8");

  private Cipher encCipher;
  private Cipher decCipher;
  private Mac macInstance;

  private int curBulkSize = 0;
  private Map<String, HashMap<String, ByteIterator>> curBulk = new HashMap<>();
  private List<String> prevBulkKeys = new ArrayList<>();
  private ThreadPoolExecutor pool = (ThreadPoolExecutor) Executors.newFixedThreadPool(VERIFICATION_QUERIES_POOL_SIZE);
  private int bulkSize;
  private int p;

  private String host;
  private int port;
  private String password;

  public void init() throws DBException {
    try {
      Properties props = getProperties();

      String portString = props.getProperty(PORT_PROPERTY);
      if (portString != null) {
        port = Integer.parseInt(portString);
      } else {
        port = Protocol.DEFAULT_PORT;
      }
      host = props.getProperty(HOST_PROPERTY);

      jedis = new Jedis(host, port);
      jedis.connect();

      password = props.getProperty(PASSWORD_PROPERTY);
      if (password != null) {
        jedis.auth(password);
      }

      bulkSize = Integer.parseInt(props.getProperty(BULK_SIZE_PROPERTY));
      p = Integer.parseInt(props.getProperty(P_PARAM_PROPERTY));

      SecretKey ke = new SecretKeySpec(props.getProperty(ENC_KEY_PROPERTY).getBytes(), "AES");
      encCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      encCipher.init(Cipher.ENCRYPT_MODE, ke);
      decCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      decCipher.init(Cipher.DECRYPT_MODE, ke);
      SecretKey km = new SecretKeySpec(props.getProperty(AUTH_KEY_PROPERTY).getBytes(), "HmacSHA256");
      macInstance = Mac.getInstance("HmacSHA256");
      macInstance.init(km);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RuntimeException("Initialization failed !");
    }
  }

  @Override
  public Status read(String table, String key, Set<String> fields, HashMap<String, ByteIterator> result){
    Map <String, String> map = jedis.hgetAll(key);
    String macVal = map.get(MAC_LABEL);
    map.remove(MAC_LABEL);
    if (!macVal.equals(hmac(key, map, macInstance))) {
      throw new SecurityException("Value was modified !");
    }
    pool.execute(new VerificationQueriesExecutor(map.get(LINK_DATA_LABEL), decCipher, host, password, port));
    map.remove(LINK_DATA_LABEL);
    StringByteIterator.putAllAsByteIterators(result, map);
    return result.isEmpty() ? Status.ERROR : Status.OK;
  }

  public Status insert(String table, String key, HashMap<String, ByteIterator> values) {
    curBulk.put(key, values);
    curBulkSize++;
    if (curBulkSize < bulkSize) {
      return Status.BATCHED_OK;
    } else {
      Status result = putBulk(curBulk);
      if (result.isOk()) {
        curBulkSize = 0;
        curBulk.clear();
      }
      return result;
    }
  }

  private Status putBulk(Map<String, HashMap<String, ByteIterator>> bulk) {
    List<String> keys = new ArrayList<>(bulk.keySet());
    for (String key : keys) {
      Set<String> linkData = getLinkData(keys, key);
      HashMap<String, String> values = StringByteIterator.getStringMap(bulk.get(key));
      values.put(LINK_DATA_LABEL, encLinkData(linkData, encCipher));
      values.put(MAC_LABEL, hmac(key, values, macInstance));
      String result = jedis.hmset(key, values);
      if (!result.equals("OK")) {
        return ERROR;
      }
    }
    prevBulkKeys = new ArrayList<>(bulk.keySet());
    return OK;
  }

  private Set<String> getLinkData(List<String> bulkKeys, String key) {
    Set<String> result = getNextKeys(bulkKeys, key, p/2);
    if (!prevBulkKeys.isEmpty()) {
      result.addAll(getNextKeys(prevBulkKeys, key, p / 2));
    }
    return result;
  }

  private Set<String> getNextKeys(List<String> keys, String key, int keysNum) {
    Set<String> result = new HashSet<>(keysNum);
    while (result.size() < keysNum) {
      String nextKey = keys.get(RAND.nextInt(keys.size()));
      if (!nextKey.equals(key)) {
        result.add(nextKey);
      }
    }
    return result;
  }

  private static String encLinkData(Set<String> linkData, Cipher encCipher) {
    try {
      return Base64.getEncoder().encodeToString(encCipher.doFinal(serializeLinkData(linkData).getBytes(CHARSET)));
    } catch (Exception e) {
      throw new RuntimeException("Failed to encrypt linking data");
    }
  }

  private static String serializeLinkData(Set<String> linkData) {
    String result = "";
    for (String s : linkData) {
      result += s + LINK_DATA_DELIMITER;
    }
    if (!result.isEmpty()) {
      result = result.substring(0, result.length() - 1);
    }
    return result;
  }

  private static String decLinkData(String linkData, Cipher decCipher) {
    try {
      return new String(decCipher.doFinal(Base64.getDecoder().decode(linkData)), CHARSET);
    } catch (Exception e) {
      throw new RuntimeException("Failed to decrypt linking data");
    }
  }

  private String hmac(String key, Map<String, String> values, Mac mac){
    StringBuilder stringBuilder = new StringBuilder(key);
    for (String s : values.keySet()){
      stringBuilder.append(s).append(values.get(s));
    }
    byte [] data = stringBuilder.toString().getBytes(CHARSET);
    byte [] macVal = mac.doFinal(data);
    return Base64.getEncoder().encodeToString(macVal);
  }

  private static class VerificationQueriesExecutor implements Runnable{

    private String linkData;
    private Cipher decCipher;
    private String host;
    private String password;
    private int port;

    VerificationQueriesExecutor(String linkData, Cipher decCipher, String host, String password, int port){
      this.linkData = linkData;
      this.decCipher = decCipher;
      this.host = host;
      this.password = password;
      this.port = port;
    }

    @Override
    public void run() {
      Jedis jedis = new Jedis(host, port);
      try {
        if (password != null) {
          jedis.auth(password);
        }
        String decLinkData = decLinkData(linkData, decCipher);
        String[] keys = decLinkData.split(LINK_DATA_DELIMITER);
        for (String key : keys) {
          Map<String, String> result = jedis.hgetAll(key);
          if (result == null || result.isEmpty()) {
            throw new SecurityException("Tuple is missing !");
          }
        }
      }catch(JedisConnectionException e){
        System.out.println("Connection Failure !");
      }finally{
        jedis.disconnect();
      }
    }
  }

  public void cleanup() throws DBException {
    jedis.disconnect();
    pool.shutdownNow();
  }

  @Override //not supported in our system model
  public Status delete(String table, String key) {
    return OK;
  }

  @Override //not supported in our system model
  public Status update(String table, String key, HashMap<String, ByteIterator> values) {
    return OK;
  }

  @Override //not supported in our system model
  public Status scan(String table, String startkey, int recordcount, Set<String> fields,
                     Vector<HashMap<String, ByteIterator>> result) {
    return OK;
  }


}
