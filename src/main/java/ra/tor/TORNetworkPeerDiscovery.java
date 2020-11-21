package ra.tor;

import ra.util.tasks.BaseTask;
import ra.util.tasks.TaskRunner;

public class TORNetworkPeerDiscovery extends BaseTask {

    private TORClientService service;

    public TORNetworkPeerDiscovery(TORClientService service, TaskRunner taskRunner) {
        super(TORNetworkPeerDiscovery.class.getSimpleName(), taskRunner);
        this.service = service;
    }

    @Override
    public Boolean execute() {
        return null;
    }
}
