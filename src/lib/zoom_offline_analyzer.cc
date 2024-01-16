#include "zoom_offline_analyzer.h"
#include <set>
#include <iostream>
#include <numeric>
#include <unordered_map>
#include <string>

void zoom::offline_analyzer::add(const zoom::pkt &pkt)
{

    _pkts_processed++;

    if (_pkt_log.enabled)
    {
        _write_pkt_log(pkt);
    }

    if (pkt.flags.rtp)
    {

        auto key = zoom::media_stream_key::from_pkt(pkt);

        auto streams_it = _media_streams.find(key);

        if (streams_it == _media_streams.end())
        {

            if ((streams_it = _insert_new_stream(key, pkt)) == _media_streams.end())
            {
                std::cerr << "error: failed setting up stream state, exiting." << std::endl;
                return;
            }
        }

        timeval tv{pkt.ts.s, (int)pkt.ts.us};

        streams_it->second.analyzer.add(
            pkt.proto.rtp.seq, pkt.proto.rtp.ts, tv, pkt.udp_pl_len, {.rtp_ext1 = {pkt.rtp_ext1[0], pkt.rtp_ext1[1], pkt.rtp_ext1[2]}, .pkt_type = pkt.zoom_media_type, .pkts_hint = pkt.pkts_in_frame});
    }
}

zoom::offline_analyzer::media_streams_map::iterator zoom::offline_analyzer::_insert_new_stream(
    const zoom::media_stream_key &stream_key, const zoom::pkt &pkt)
{

    // auto stream_meta = zoom::media_stream_meta::from_pkt(pkt);

    auto frame_handler = [this](const auto &analyzer, const auto &frame)
    {
        _frame_handler(analyzer, frame);
    };

    auto stats_handler = [this](const auto &analyzer, unsigned report_count,
                                unsigned ts, const auto &stats) -> void
    {
        _stats_handler(analyzer, report_count, ts, stats);
    };

    // use 8,000 kHz for audio, 90,000 kHz for video
    auto sampling_rate = pkt.zoom_media_type == 15 ? 8000 : 90000;

    stream_analyzer analyzer(frame_handler, stats_handler, sampling_rate, stream_key);

    const auto &[it, success] = _media_streams.emplace(stream_key, stream_data{
                                                                       .analyzer = std::move(analyzer)});

    return success ? it : _media_streams.end();
}

static inline unsigned long long rtp_ts_to_wallclock_ms(std::uint32_t rtp_ts,
                                                        unsigned sampling_rate_khz)
{
    return (unsigned long long)((double)rtp_ts / (double)sampling_rate_khz * 1000);
}

static inline unsigned long long timeval_to_ms(timeval tv)
{
    // Ensure one of the operands is a floating-point type
    return static_cast<unsigned long long>((static_cast<double>(tv.tv_sec) * 1000.0) + (static_cast<double>(tv.tv_usec) / 1000.0));
}

int getGroupNumber(std::uint32_t ssrc, std::unordered_map<std::uint32_t, int> &ssrcToCategory, int &categoryCounter)
{
    // Check if the SSRC is already in the map
    if (ssrcToCategory.find(ssrc) == ssrcToCategory.end())
    {
        // If not, assign a new category
        ssrcToCategory[ssrc] = categoryCounter++;
    }

    // Return the group number
    return ssrcToCategory[ssrc];
}

double calculateAverage(const std::vector<unsigned long long> &values)
{
    if (values.empty())
    {
        // Avoid division by zero for an empty vector
        std::cerr << "Error: Cannot calculate average for an empty vector.\n";
        return 0.0;
    }

    unsigned long long sum = 0;

    for (const auto &value : values)
    {
        // std::cout << "value in the array: " << value << std::endl;
        sum += value;
    }

    return static_cast<unsigned long long>(sum) / values.size();
}

std::unordered_map<std::uint32_t, int> ssrcToCategory;
int categoryCounter = 0;

std::map<int, std::vector<unsigned long long>> rtpMap;
std::map<int, std::vector<unsigned long long>> tsMap;

void zoom::offline_analyzer::_frame_handler(const stream_analyzer &a,
                                            const struct stream_analyzer::frame &f)
{

    auto meta = a.meta();
    const auto *first_pkt = &(f.pkts[0]);

    // if length of first100rtp is < 100, append to id and DO NOTHING ELSE

    // if length of first 100 rtp is >= 100, do the following
    // get avg of the first 100, subtract for each

    // modifications begin here
    if (_frame_log.enabled)
    {
        std::uint32_t rtp_ts = f.rtp_ts;

        // must subtract the average of first 100 sec to this
        // auto times = timeval_to_ms(f.ts_max);
        auto times = timeval_to_ms(f.ts_max);
        // std::cout << "Times: " << times << std::endl;
        auto rtps = rtp_ts_to_wallclock_ms(rtp_ts, 90000);

        // check if the media is video
        // pkt.proto.rtp.pt

        if (first_pkt->meta.pkt_type == 16 && uniqueRtpTimestamps.insert(rtps).second)
        {

            int groupNumber = getGroupNumber(meta.rtp_ssrc, ssrcToCategory, categoryCounter);

            // std::cout << "SSRC: " << meta.rtp_ssrc << " Group Number: " << groupNumber << std::endl;

            if (rtpMap[groupNumber].size() < 100)
            {
                // std::cout << "rtp: " << rtps << std::endl;
                // std::cout << "ts: " << times << std::endl;
                rtpMap[groupNumber].push_back(rtps);
                tsMap[groupNumber].push_back(times);
            }

            // unsigned long long sum_rtp = std::accumulate(first100rtp.begin(), first100rtp.end(), 0ULL);
            // double avg_rtp = static_cast<double>(sum_rtp) / first100rtp.size();
            double avg_rtp = calculateAverage(rtpMap[groupNumber]);

            double avg_ts = calculateAverage(tsMap[groupNumber]);

            // std::cout << "rtp avg: " << avg_rtp << std::endl;
            // std::cout << "ts avg: " << avg_ts << std::endl;

            double fn_time = times - avg_ts;
            double fn_rtp = rtps - avg_rtp;
            double diff = fn_time - fn_rtp;

            _write_frame_log(a, f, fn_time, fn_rtp, groupNumber, diff);
        }
    }
}

void zoom::offline_analyzer::_stats_handler(const stream_analyzer &a, unsigned report_count,
                                            unsigned ts, const struct stream_analyzer::stats &c)
{

    if (_stats_log.enabled)
        _write_stats_log(a.meta(), report_count, ts, c);
}

void zoom::offline_analyzer::write_streams_log()
{

    _streams_log.stream << "rtp_ssrc,media_type,stream_type,ip_src,tp_src,ip_dst,tp_dst,"
                        << "start_ts_s,start_ts_us,end_ts_s,end_ts_us,start_rtp_ts,end_rtp_ts,"
                        << "pkts,bytes" << std::endl;

    for (const auto &[key, data] : _media_streams)
    {

        _streams_log.stream
            << key.rtp_ssrc << ","
            << zoom::media_type_to_char(key.media_type) << ","
            << zoom::stream_type_to_char(key.stream_type) << ","

            << net::ipv4::addr_to_str(key.ip_5t.ip_src) << ","
            << key.ip_5t.tp_src << ","
            << net::ipv4::addr_to_str(key.ip_5t.ip_dst) << ","
            << key.ip_5t.tp_dst << ","

            << data.analyzer.timestamps().first_timeval.tv_sec << ","
            << data.analyzer.timestamps().first_timeval.tv_usec << ","
            << data.analyzer.timestamps().last_timeval.tv_sec << ","
            << data.analyzer.timestamps().last_timeval.tv_usec << ","

            << data.analyzer.timestamps().first_rtp << ","
            << data.analyzer.timestamps().last_rtp << ","

            << data.analyzer.stats().total_pkts << ","
            << data.analyzer.stats().total_bytes
            << std::endl;
    }
}

void zoom::offline_analyzer::_write_pkt_log(const zoom::pkt &pkt)
{

    _pkt_log.stream << std::dec << pkt.ts.s << "," << pkt.ts.us << ",u,";

    if (pkt.flags.srv)
    {
        _pkt_log.stream << "s,";
    }
    else if (pkt.flags.p2p)
    {
        _pkt_log.stream << "p,";
    }
    else
    {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream << pkt.ip_5t << ",";

    // TODO: handle screen share
    if (pkt.zoom_media_type == zoom::AUDIO_TYPE)
    {
        _pkt_log.stream << "a,";
    }
    else if (pkt.zoom_media_type == zoom::VIDEO_TYPE)
    {
        _pkt_log.stream << "v,";
    }
    else
    {
        _pkt_log.stream << "NA,";
    }

    if (pkt.pkts_in_frame)
    {
        _pkt_log.stream << pkt.pkts_in_frame << ",";
    }
    else
    {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream
        << std::dec << (unsigned)pkt.proto.rtp.ssrc << ","
        << std::dec << (unsigned)pkt.proto.rtp.pt << ","
        << std::dec << (unsigned)pkt.proto.rtp.seq << ","
        << std::dec << (unsigned)pkt.proto.rtp.ts << ","
        << std::dec << (unsigned)pkt.udp_pl_len << ",";

    if (pkt.rtp_ext1[0] != 0 || pkt.rtp_ext1[1] != 0 || pkt.rtp_ext1[2] != 0)
    {
        _pkt_log.stream << "0x";
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned)pkt.rtp_ext1[0];
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned)pkt.rtp_ext1[1];
        _pkt_log.stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned)pkt.rtp_ext1[2];
        _pkt_log.stream << ",";
    }
    else
    {
        _pkt_log.stream << "NA,";
    }

    _pkt_log.stream << "0" << std::endl;
}

void zoom::offline_analyzer::_write_frame_log(const stream_analyzer &a, const stream_analyzer::frame &f, double times, double rtps, int groupNumber, double diff)
{

    auto meta = a.meta();
    const auto *first_pkt = &(f.pkts[0]);

    _frame_log.stream
        << meta.ip_5t << ","
        << std::dec << (unsigned)meta.rtp_ssrc << ","
        << std::dec << (unsigned)first_pkt->meta.pkt_type << ","
        //<< std::hex << std::setw(2) << std::setfill('0')
        << (unsigned)first_pkt->meta.rtp_ext1[0]
        << std::hex << std::setw(2) << std::setfill('0')
        << (unsigned)first_pkt->meta.rtp_ext1[1]
        << std::hex << std::setw(2) << std::setfill('0')
        << (unsigned)first_pkt->meta.rtp_ext1[2] << ","
        << std::dec << (unsigned)f.ts_min.tv_sec << ","
        << std::dec << (unsigned)f.ts_min.tv_usec << ","
        << std::dec << (unsigned)f.ts_max.tv_sec << ","
        << std::dec << (unsigned)f.ts_max.tv_usec << ","
        << std::dec << (unsigned)f.rtp_ts << ","
        << std::dec << (unsigned)f.pkts_seen << ","
        << std::dec << (unsigned)first_pkt->meta.pkts_hint << ","
        << std::dec << (unsigned)f.total_pl_len << ","
        << std::dec << (unsigned)f.fps << ","
        << std::setprecision(5) << f.jitter << ","
        << std::dec << times << "," // Add the new column (diff) to the CSV
        << std::dec << (unsigned)rtps << ","
        << std::dec << (unsigned)diff << ","
        << std::dec << (unsigned)groupNumber
        << std::endl;
}

void zoom::offline_analyzer::_write_stats_log(const zoom::media_stream_key &k, unsigned report_count,
                                              unsigned ts,
                                              const struct stream_analyzer::stats &c)
{

    _stats_log.stream
        << ts << ","
        << report_count << ","

        << k.rtp_ssrc << ","
        << zoom::media_type_to_char(k.media_type) << ","
        << zoom::stream_type_to_char(k.stream_type) << ","

        << net::ipv4::addr_to_str(k.ip_5t.ip_src) << ","
        << k.ip_5t.tp_src << ","
        << net::ipv4::addr_to_str(k.ip_5t.ip_dst) << ","
        << k.ip_5t.tp_dst << ","

        << std::dec << c.total_pkts << ","
        << std::dec << c.total_bytes << ","

        << std::dec << c.lost_pkts << ","
        << std::dec << c.duplicate_pkts << ","
        << std::dec << c.out_of_order_pkts << ","

        << std::dec << c.total_frames << ","
        << std::dec << c.mean_frame_size() << ","
        << std::dec << c.mean_jitter()
        << std::endl;
}
