#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <string>

struct Frame
{
    int ip_proto;
    std::string ip_src;
    int tp_src;
    std::string ip_dst;
    int tp_dst;
    unsigned int ssrc;
    std::string media_type;
    int rtp_ext1;
    unsigned long long min_ts_s;
    unsigned long long min_ts_us;
    unsigned long long max_ts_s;
    unsigned long long max_ts_us;
    unsigned long long rtp_ts;
    int pkts_seen;
    // new
    int pkts_hint;
    int frame_size;
    int fps;
    float jitter_ms;
    int times;
    int rtps;
    int diff;
    int group;
    int delta_rtp = 0;
    int skip = 0;
    int freeze = 0;
};

void parseLine(const std::string &line, std::vector<Frame> &stats, int lineNumber)
{
    // std::cout << "Parsing line " << lineNumber << ": " << line << std::endl;

    // Split the line by commas
    std::vector<std::string> fields;
    std::istringstream iss(line);
    std::string field;
    while (std::getline(iss, field, ','))
    {
        fields.push_back(field);
    }

    // Print out the number of fields detected
    // std::cout << "Number of fields detected in line " << lineNumber << ": " << fields.size() << std::endl;

    // Ensure there are at least two fields in the line
    if (fields.size() < 2)
    {
        std::cerr << "Error: Line " << lineNumber << " does not contain enough fields: " << line << std::endl;
        return;
    }

    // Create a Frame object with the first two fields
    Frame frame;
    try
    {
        frame.ip_proto = std::stoi(fields[0]);
        frame.ip_src = fields[1];
        frame.tp_src = std::stoi(fields[2]);
        frame.ip_dst = fields[3];
        frame.tp_dst = std::stoi(fields[4]);
        frame.ssrc = std::stoul(fields[5]);
        frame.media_type = fields[6];
        frame.rtp_ext1 = std::stoi(fields[7]);
        frame.min_ts_s = std::stoull(fields[8]);
        frame.min_ts_us = std::stoull(fields[9]);
        frame.max_ts_s = std::stoull(fields[10]);
        frame.max_ts_us = std::stoull(fields[11]);
        frame.rtp_ts = std::stoull(fields[12]);
        frame.pkts_seen = std::stoi(fields[13]);
        // new
        frame.pkts_hint = std::stoi(fields[14]);
        frame.frame_size = std::stoi(fields[15]);
        frame.fps = std::stoi(fields[16]);
        frame.jitter_ms = std::stof(fields[17]);
        frame.times = std::stoi(fields[18]);
        frame.rtps = std::stoi(fields[19]);
        frame.diff = std::stoi(fields[20]);
        frame.group = std::stoi(fields[21]);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to parse line " << lineNumber << ": " << e.what() << std::endl;
        return;
    }

    stats.push_back(frame);
}

// Function to split data based on a column value
std::map<int, std::vector<Frame> > splitByValue(const std::vector<Frame> &data, const std::string &columnName)
{
    std::map<int, std::vector<Frame> > splitTables;
    for (const auto &frame : data)
    {
        splitTables[frame.group].push_back(frame);
    }
    return splitTables;
}

bool compareByRTPS(const Frame &a, const Frame &b)
{
    return a.rtps < b.rtps;
}

// Function to calculate lateness percentage
double latenessPercentJB(std::vector<Frame> frames, std::vector<double> &skipArray, std::vector<double> &freezeArray)
{
    double lateness = 0.0;
    int this_out_time = 0;

    std::sort(frames.begin(), frames.end(), compareByRTPS);

    for (size_t i = 0; i < frames.size() - 1; ++i)
    {
        frames[i].delta_rtp = frames[i + 1].rtps - frames[i].rtps;
    }
    for (size_t i = 0; i < frames.size() - 1; ++i)
    {
        int prev_play_time = this_out_time;
        this_out_time = std::max(prev_play_time, std::max(frames[i].times, frames[i].rtps));
        if (frames[i + 1].times > frames[i + 1].rtps)
        {
            int x = frames[i + 1].times - std::max(this_out_time, frames[i + 1].rtps);
            if (x > 0)
            {
                frames[i].freeze = x;
            }
            else
            {
                frames[i].freeze = 0;
            }
        }
        else
        {
            frames[i].freeze = 0;
        }
        if (i > 0)
        {
            if (this_out_time - prev_play_time < frames[i - 1].delta_rtp)
            {
                frames[i - 1].skip = frames[i - 1].delta_rtp - (this_out_time - prev_play_time);
                frames[i - 1].freeze = 0;
            }
            else
            {
                frames[i - 1].skip = 0;
            }
        }
        if (!std::isnan(frames[i].freeze))
        {
            lateness += frames[i].freeze;
        }
    }

    unsigned long long min_s = std::numeric_limits<unsigned long long>::max();
    unsigned long long min_us = std::numeric_limits<unsigned long long>::max();
    unsigned long long max_s = std::numeric_limits<unsigned long long>::min();
    unsigned long long max_us = std::numeric_limits<unsigned long long>::min();

    // Find the minimum and maximum values
    for (const auto &frame : frames)
    {
	skipArray.push_back(frame.skip);
	freezeArray.push_back(frame.freeze);
        min_s = std::min(min_s, frame.min_ts_s);
        if (frame.min_ts_s == min_s)
        {
            min_us = std::min(min_us, frame.min_ts_us);
        }
        max_s = std::max(max_s, frame.max_ts_s);
        if (frame.max_ts_s == max_s)
        {
            max_us = std::max(max_us, frame.max_ts_us);
        }
    }

    // Calculate the total
    unsigned long long total = (max_s * 1000 + max_us / 1000) - (min_s * 1000 + min_us / 1000);

    if (total == 0)
        return 0;
    return lateness / total;
}

int main()
{
    std::ifstream file("frames.csv");
    if (!file.is_open())
    {
        std::cerr << "Error: Failed to open file 'frames.csv'" << std::endl;
        return 1;
    }

    std::vector<Frame> stats;
    std::string line;
    int lineNumber = 0;
    while (std::getline(file, line))
    {
        ++lineNumber;
        parseLine(line, stats, lineNumber);
    }

    if (stats.empty())
    {
        std::cout << "stats is empty" << std::endl;
    }
    std::map<int, std::vector<Frame> > groupings = splitByValue(stats, "group");

    // Calculate lateness percentage
    std::vector<double> special_percent_list;
    std::vector<double> skipArray;
    std::vector<double> freezeArray;
    for (const auto &group : groupings)
    {
        std::cout << "grouping" << std::endl;
        double result = latenessPercentJB(group.second, skipArray, freezeArray);
        std::cout << "Result: " << result << std::endl;
        if (!std::isnan(result) && result < 1 && result >= 0)
        {
            special_percent_list.push_back(result);
        }
    }

    // Export to CSV
    std::ofstream output("special_percent_list.csv");
    for (const auto &percent : special_percent_list)
    {
        output << percent << std::endl;
    }
    
    std::ofstream output1("skip_list.csv");
    for (const auto &skip : skipArray)
    {
        output1 << skip << std::endl;
    }
 
    std::ofstream output2("freeze_list.csv");
    for (const auto &freeze : freezeArray)
    {
        output2 << freeze << std::endl;
    }
    return 0;
}
