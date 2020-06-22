package ra.tor;

import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.DefaultHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 *
 */
public class TORHiddenServiceHandler extends DefaultHandler implements AsynchronousEnvelopeHandler {

    private static Logger LOG = Logger.getLogger(TORHiddenServiceHandler.class.getName());

    private Map<Long,ClientHold> requests = new HashMap<>();
    private String id;
    private String serviceName;
    private String[] parameters;
    protected ClearnetSession clearnetSession;
    private HttpSession activeSession;

    public TORHiddenServiceHandler() {}

    @Override
    public void setClearnetSession(ClearnetSession clearnetSession) {
        this.clearnetSession = clearnetSession;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public void setParameters(String[] parameters) {
        this.parameters = parameters;
    }

    /**
     *
     * @param target the path sent after the ip address + port
     * @param baseRequest
     * @param request
     * @param response
     * @throws IOException
     */
    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
        LOG.info("HTTP Hidden Service Handler called; target: "+target);
        if("/test.html".equals(target)) {
            response.setContentType("text/html");
            response.getWriter().print("<html><body>"+serviceName+" Available</body></html>");
            response.setStatus(200);
            baseRequest.setHandled(true);
            return;
        } else if("/test.json".equals(target)) {
            response.setContentType("application/json");
            response.getWriter().print("{\n\t\"serviceName\": \""+serviceName+"\",\n\t\"status\": Available\n}");
            response.setStatus(200);
            baseRequest.setHandled(true);
            return;
        }
        String errorMsg = verifyRequest(target, request);
        if(errorMsg != null) {
            response.setContentType("application/json");
            response.getWriter().print("{\n\t\"serviceName\": \""+serviceName+"\",\n\t\"status\": Available, \n\t\"error\": \""+errorMsg+"\"\n}");
            response.setStatus(400); // Bad request error
            baseRequest.setHandled(true);
            return;
        }

        long now = System.currentTimeMillis();
        if(!request.getSession().getId().equals(activeSession.getId())) {
            activeSession = request.getSession();
            request.getSession().setMaxInactiveInterval(ClearnetSession.SESSION_INACTIVITY_INTERVAL);
            clearnetSession.setSessionId(activeSession.getId());
        } else if(clearnetSession.getLastRequestTime() + now > ClearnetSession.SESSION_INACTIVITY_INTERVAL * 1000){
            request.getSession().invalidate();
            activeSession = request.getSession(true);
            request.getSession().setMaxInactiveInterval(ClearnetSession.SESSION_INACTIVITY_INTERVAL);
            clearnetSession.setSessionId(activeSession.getId());
        }

        clearnetSession.setLastRequestTime(now);

        String json = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
        Map<String,Object> payload = (Map<String,Object>)JSONParser.parse(json);
        String type = (String)payload.get("type");
        if(type==null) {
            String msg = "'type' is a required parameter.";
            LOG.warning(msg);
            response.setContentType("application/json");
            response.getWriter().print("{\n\t\"serviceName\": \""+serviceName+"\",\n\t\"status\": Available, \n\t\"error\": \""+msg+"\"\n}");
            response.setStatus(400); // Bad request error
            baseRequest.setHandled(true);
            return;
        }
        boolean isNetworkOp = false;
        boolean isNetworkPacket = false;
        if(type.startsWith("io.onemfive.network.ops"))
            isNetworkOp = true;
        else if(type.startsWith("io.onemfive.network"))
            isNetworkPacket = true;
        if(!isNetworkOp && !isNetworkPacket) {
            String msg = payload.get("type")+ " Unsupported";
            LOG.warning(msg);
            response.setContentType("application/json");
            response.getWriter().print("{\n\t\"serviceName\": \""+serviceName+"\",\n\t\"status\": Available, \n\t\"error\": \""+msg+"\"\n}");
            response.setStatus(400); // Bad request error
            baseRequest.setHandled(true);
            return;
        }

        if(isNetworkOp) {
            NetworkOp op = parseNetworkOp(target, request, clearnetSession.sessionId, payload);
            ClientHold clientHold = new ClientHold(target, baseRequest, request, response, op);
            requests.put((long)op.id, clientHold);

            clearnetSession.handle(op); // Synchronous call

            if(op instanceof NetworkRequestOp && ((NetworkRequestOp)op).responseOp!=null) {
                response.setContentType("application/json");
                response.getWriter().print(((NetworkRequestOp)op).responseOp.toJSON());
                response.setStatus(200);
            } else  {
                response.setStatus(204);
            }
            baseRequest.setHandled(true);

        } else {
            NetworkPacket packet = parseNetworkPacket(target, request, clearnetSession.sessionId, payload);
            ClientHold clientHold = new ClientHold(target, baseRequest, request, response, packet);
            requests.put(packet.getEnvelope().getId(), clientHold);

            clearnetSession.sendIn(packet); // asynchronous call upon; returns upon reaching Message Channel's queue in Service Bus

            if (DLC.getErrorMessages(packet.getEnvelope()).size() > 0) {
                // Just 500 for now
                List<String> errMsgs = DLC.getErrorMessages(packet.getEnvelope());
                StringBuilder sb = new StringBuilder();
                sb.append("{\n\t\"serviceName\": \""+serviceName+"\",\n\t\"status\": Available, \n\t\"error\": [");
                boolean first = true;
                for(String err : errMsgs) {
                    if(first) {
                        sb.append("\"" + err + "\"");
                    } else {
                        sb.append(",\"" + err + "\"");
                        first = false;
                    }
                }
                sb.append("]\n}");
                String msg = sb.toString();
                LOG.warning(msg);
                response.setContentType("application/json");
                response.getWriter().print(msg);
                response.setStatus(500);
                baseRequest.setHandled(true);
                requests.remove(packet.getId());
            } else {
                // Hold Thread until response or 60 seconds
//            LOG.info("Holding HTTP Request for up to 60 seconds waiting for internal asynch response...");
                String result = clientHold.hold(60 * 1000, packet.getId()); // hold for 60 seconds or until interrupted
                if (result != null) {
                    response.setContentType("application/json");
                    response.getWriter().print("{\"" + serviceName + "\": Unavailable, " + result + "}");
                    response.setStatus(500);
                    baseRequest.setHandled(true);
                }
            }
        }
    }

    protected String verifyRequest(String target, HttpServletRequest request) {
        String msg = null;
        if(!"application/json".equals(request.getContentType())) {
            msg = request.getContentType()+" not supported by 1M5 TOR Hidden Services, only application/json.";
            LOG.warning(msg);
        } else if(!"POST".equals(request.getMethod())) {
            msg = "Only POST supported by 1M5 TOR Hidden Services.";
            LOG.warning(msg);
        }
        return msg;
    }

    protected NetworkOp parseNetworkOp(String target, HttpServletRequest request, String sessionId, Map<String,Object> payload) {
        LOG.info("Parsing request into NetworkOp...");
        String type = (String)payload.get("type");
        NetworkOp op = null;
        try {
            op = (NetworkOp)Class.forName(type).getConstructor().newInstance();
            op.fromMap(payload);
        } catch (Exception e) {
            LOG.warning(e.getLocalizedMessage());
        }
        return op;
    }

    protected NetworkPacket parseNetworkPacket(String target, HttpServletRequest request, String sessionId, Map<String,Object> payload) {
        LOG.info("Parsing request into NetworkPacket...");
        String type = (String)payload.get("type");
        NetworkPacket packet = null;
        try {
            packet = (NetworkPacket)Class.forName(type).getConstructor().newInstance();
            packet.fromMap(payload);
        } catch (Exception e) {
            LOG.warning(e.getLocalizedMessage());
            return null;
        }

        Envelope e = packet.getEnvelope();

        // Must set id in header for asynchronous support
        e.setHeader(ClearnetSession.HANDLER_ID, id);
        e.setHeader(ClearnetSession.SESSION_ID, sessionId);

        // Set path
        e.setCommandPath(target.startsWith("/")?target.substring(1):target); // strip leading slash if present
        try {
            // This is required to ensure the SensorManager knows to return the reply to the ClearnetServerSensor (ends with .json)
            URL url = new URL("http://127.0.0.1/request.json");
            e.setURL(url);
        } catch (MalformedURLException e1) {
            LOG.warning(e1.getLocalizedMessage());
        }

        // Ensure POST set
        e.setAction(Envelope.Action.POST);
        // Populate headers
        Enumeration<String> headerNames = request.getHeaderNames();
        while(headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            Enumeration<String> headerValues = request.getHeaders(headerName);
            boolean first = true;
            int i = 2;
            while(headerValues.hasMoreElements()){
                String headerValue = headerValues.nextElement();
                if(first) {
                    e.setHeader(headerName, headerValue);
                    first = false;
                } else {
                    e.setHeader(headerName + i++, headerValue);
                }
//                LOG.info("Incoming header:value="+headerName+":"+headerValue);
            }
        }

        e.setExternal(true);

        // Get post parameters if present and place as content
        Map<String,String[]> m = request.getParameterMap();
        if(m != null && !m.isEmpty()) {
            DLC.addContent(m, e);
        }

        return packet;
    }

    public void reply(Envelope e) {
        ClientHold hold = requests.get(e.getId());
        HttpServletResponse response = hold.getResponse();
        LOG.info("Updating session status from response...");
        String sessionId = (String)e.getHeader(ClearnetSession.class.getName());
        if(activeSession==null) {
            // session expired before response received so kill
            LOG.warning("Expired session before response received: sessionId="+sessionId);
            respond("{httpErrorCode=401}", "application/json", response, 401);
        } else {
            LOG.info("Active session found");
            respond(serializeContent(e), "application/json", response, 200);
        }
        hold.baseRequest.setHandled(true);
        LOG.info("Waking sleeping request thread to return response to caller...");
        hold.wake(); // Interrupt sleep to allow thread to return
        LOG.info("Unwinded request call with response.");
    }

    protected String serializeContent(Envelope e) {
        LOG.info("Serializing returned Envelope...");
        ClientHold hold = requests.get(e.getId());
        NetworkPacket requestPacket = (NetworkPacket)hold.getPayload();
        Response responsePacket = new Response(requestPacket.getId());
        // Response coming from this node
        responsePacket.setOriginationPeer(requestPacket.getToPeer());
        responsePacket.setFromPeer(requestPacket.getToPeer());
        // Response requested to go directly to destination (but may not depending on network status)
        responsePacket.setToPeer(requestPacket.getFromPeer());
        // Response needs to end up at destination
        responsePacket.setDestinationPeer(requestPacket.getFromPeer());
        // Set returned content
        responsePacket.setEnvelope(e);
        // Serialize to JSON
        return responsePacket.toJSON();
    }

    protected void respond(String body, String contentType, HttpServletResponse response, int code) {
//        LOG.info("Returning response...");
        response.setContentType(contentType);
        try {
            response.getWriter().print(body);
            response.setStatus(code);
        } catch (IOException ex) {
            LOG.warning(ex.getLocalizedMessage());
            response.setStatus(500);
        }
    }

    private class ClientHold {
        private Thread thread;
        private String target;
        private Request baseRequest;
        private HttpServletRequest request;
        private HttpServletResponse response;
        private Object payload;

        private ClientHold(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response, Object payload) {
            this.target = target;
            this.baseRequest = baseRequest;
            this.request = request;
            this.response = response;
            this.payload = payload;
        }

        private String hold(long waitTimeMs, String id) {
            long startWait = System.currentTimeMillis();
            thread = Thread.currentThread();
            try {
                Thread.sleep(waitTimeMs);
            } catch (InterruptedException e) {
                requests.remove(id);
            }
            long endWait = System.currentTimeMillis();
            if((endWait - startWait) >= waitTimeMs) {
                // Timed out - return time out error
                return "\"error\": \"Timed Out\", \"waitTimeSeconds\": "+(waitTimeMs/1000);
            }
            return null;
        }

        private void wake() {
            thread.interrupt();
        }

        private String getTarget() {
            return target;
        }

        private Request getBaseRequest() {
            return baseRequest;
        }

        private HttpServletRequest getRequest() {
            return request;
        }

        private HttpServletResponse getResponse() {
            return response;
        }

        private Object getPayload() {
            return payload;
        }
    }

}
