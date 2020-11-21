package ra.tor;

import ra.common.content.JSON;

import java.util.Map;

public class TORHS extends JSON {
    Integer virtualPort;
    Integer targetPort;
    String serviceId;
    volatile String privateKey;
    volatile Boolean newKey = false;

    public TORHS() {}

    @Override
    public Map<String, Object> toMap() {
        Map<String,Object> m = super.toMap();
        if(virtualPort!=null) m.put("virtualPort", virtualPort);
        if(targetPort!=null) m.put("targetPort", targetPort);
        if(serviceId!=null) m.put("serviceId", serviceId);
        return m;
    }

    @Override
    public void fromMap(Map<String, Object> m) {
        super.fromMap(m);
        if(m.get("virtualPort")!=null) virtualPort = (Integer)m.get("virtualPort");
        if(m.get("targetPort")!=null) targetPort = (Integer)m.get("targetPort");
        if(m.get("serviceId")!=null) serviceId = (String)m.get("serviceId");
    }
}
