#ifdef _MSC_VER
#pragma warning(disable:4244)
#endif

#include <inttypes.h>
#include <memory>
#include <time.h>


#include "api/Api.h"
#include "common/log/Log.h"
#include "common/net/Client.h"
#include "common/net/strategies/FailoverStrategy.h"
#include "common/net/strategies/SinglePoolStrategy.h"
#include "common/net/SubmitResult.h"
#include "core/Config.h"
#include "core/Controller.h"
#include "net/Network.h"
#include "net/strategies/DonateStrategy.h"
#include "workers/Workers.h"


Network::Network(xmrig::Controller *controller) :
    m_donate(nullptr),
    m_controller(controller)
{
    srand(time(0) ^ (uintptr_t) this);

    Workers::setListener(this);

    const std::vector<Pool> &pools = controller->config()->pools();

    if (pools.size() > 1) {
        m_strategy = new FailoverStrategy(pools, controller->config()->retryPause(), controller->config()->retries(), this);
    }
    else {
        m_strategy = new SinglePoolStrategy(pools.front(), controller->config()->retryPause(), controller->config()->retries(), this);
    }

    if (controller->config()->donateLevel() > 0) {
        m_donate = new DonateStrategy(controller->config()->donateLevel(), controller->config()->pools().front().user(), controller->config()->algorithm().algo(), this);
    }

    m_timer.data = this;
    uv_timer_init(uv_default_loop(), &m_timer);

    uv_timer_start(&m_timer, Network::onTick, kTickInterval, kTickInterval);
}


Network::~Network()
{
}


void Network::connect()
{
    m_strategy->connect();
}


void Network::stop()
{
    if (m_donate) {
        m_donate->stop();
    }

    m_strategy->stop();
}


void Network::onActive(IStrategy *strategy, Client *client)
{
    if (m_donate && m_donate == strategy) {
        //LOG_NOTICE("dev donate started");
        return;
    }

    m_state.setPool(client->host(), client->port(), client->ip());

    //LOG_INFO(isColors() ? "\x1B[01;37muse pool \x1B[01;36m%s:%d \x1B[01;30m%s" : "use pool %s:%d %s", client->host(), client->port(), client->ip());
}


void Network::onJob(IStrategy *strategy, Client *client, const Job &job)
{
    if (m_donate && m_donate->isActive() && m_donate != strategy) {
        return;
    }

    setJob(client, job, m_donate == strategy);
}


void Network::onJobResult(const JobResult &result)
{
    if (result.poolId == -1 && m_donate) {
        m_donate->submit(result);
        return;
    }

    m_strategy->submit(result);
}


void Network::onPause(IStrategy *strategy)
{
    if (m_donate && m_donate == strategy) {
        //LOG_NOTICE("dev donate finished");
        m_strategy->resume();
    }

    if (!m_strategy->isActive()) {
        //LOG_ERR("no active pools, stop mining");
        m_state.stop();
        return Workers::pause();
    }
}


void Network::onResultAccepted(IStrategy *strategy, Client *client, const SubmitResult &result, const char *error)
{
    m_state.add(result, error);

    if (error) {
        //LOG_INFO(isColors() ? "\x1B[01;31mrejected\x1B[0m (%" PRId64 "/%" PRId64 ") diff \x1B[01;37m%u\x1B[0m \x1B[31m\"%s\"\x1B[0m \x1B[01;30m(%" PRIu64 " ms)"
        //                    : "wadaw (%" PRId64 "/%" PRId64 ") diff %u \"%s\" (%" PRIu64 " ms)",
        //         m_state.accepted, m_state.rejected, result.diff, error, result.elapsed);
    }
    else {
        //LOG_INFO(isColors() ? "\x1B[01;32maccepted\x1B[0m (%" PRId64 "/%" PRId64 ") diff \x1B[01;37m%u\x1B[0m \x1B[01;30m(%" PRIu64 " ms)"
        //                    : "siap (%" PRId64 "/%" PRId64 ") diff %u (%" PRIu64 " ms)",
        //         m_state.accepted, m_state.rejected, result.diff, result.elapsed);
    }
}


bool Network::isColors() const
{
    return m_controller->config()->isColors();
}


void Network::setJob(Client *client, const Job &job, bool donate)
{
    //LOG_INFO(isColors() ? MAGENTA_BOLD("new job") " from " WHITE_BOLD("%s:%d") " diff " WHITE_BOLD("%d") " algo " WHITE_BOLD("%s")
    //                    : "anyar from %s:%d diff %d algo %s",
    //         client->host(), client->port(), job.diff(), job.algorithm().shortName());

    m_state.diff = job.diff();
    Workers::setJob(job, donate);
}


void Network::tick()
{
    const uint64_t now = uv_now(uv_default_loop());

    m_strategy->tick(now);

    if (m_donate) {
        m_donate->tick(now);
    }

#   ifndef XMRIG_NO_API
    Api::tick(m_state);
#   endif
}


void Network::onTick(uv_timer_t *handle)
{
    static_cast<Network*>(handle->data)->tick();
}
