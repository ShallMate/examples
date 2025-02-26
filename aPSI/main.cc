#include <cstddef>
#include <string>
#include <vector>
#include <fstream>
#include <utility>
#include <memory>
#include <iostream>


#include <apsi/sender.h>
#include "apsi/oprf/oprf_receiver.h"
#include <apsi/network/stream_channel.h>
#include "apsi/receiver.h"
#include "apsi/util/utils.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

#include <json/json.h> // 假设你使用的是 jsoncpp 库

using namespace std;
using namespace apsi;


std::vector<uint128_t> CreateRangeItems(size_t start, size_t size) {
  std::vector<uint128_t> ret(size);
   yacl::parallel_for(0, size, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
        ret[idx] = yacl::crypto::Blake3_128(std::to_string(start + idx));
    }  });
  return ret;
}

std::vector<string> ItemsToStr(std::vector<uint128_t>& items) {
  std::vector<string> ret(items.size());
  yacl::parallel_for(0, items.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
        ret[idx] = yacl::SerializeUint128(items[idx]);
    }
  });
  return ret;
}




int main() {
    // Use the maximum number of threads available on the machine
    ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
    // Full logging to console
    // Log::SetLogLevel(Log::Level::all);
    // Log::SetConsoleDisabled(false);

    stringstream channel_stream;
    network::StreamChannel channel(channel_stream);

    // 读取 params.json 配置文件
    ifstream params_fs("/home/lgw/yacl/examples/apsitest/params.json", ios::in);
    if (!params_fs.is_open()) {
        cerr << "Failed to open params.json file." << endl;
        return 1;
    }

    // 拼接 JSON 文件内容
    string params_str;
    string curr_line;
    while (getline(params_fs, curr_line)) {
        params_str.append(curr_line);
        params_str.append("\n");
    }
    // cout << "Loaded JSON content:\n" << params_str << endl;
    PSIParams params = PSIParams::Load(params_str);  // 使用 Load 加载配置文件
    // Create the Sender's database (we are setting up an unlabeled SenderDB here).

    shared_ptr<sender::SenderDB> sender_db = make_shared<sender::SenderDB>(params);
    // Let's insert a couple items
    size_t ns = 1 << 20;
    std::vector<uint128_t> raw_sender_items = CreateRangeItems(1, ns);
    // cout << "Items created" << endl;
    std::vector<string> raw_sender_items_str = ItemsToStr(raw_sender_items);

    // We need to convert the strings to Item objects
    vector<Item> sender_items(raw_sender_items_str.begin(), raw_sender_items_str.end());


    // Now suppose the Receiver wants to query for a couple items
    size_t nr = 1 << 12;
    vector<uint128_t> raw_receiver_items = CreateRangeItems(1, nr);
    vector<string> raw_receiver_items_str = ItemsToStr(raw_receiver_items);

    // We need to convert the strings to Item objects
    vector<Item> receiver_items(raw_receiver_items_str.begin(), raw_receiver_items_str.end());

    // Insert the items in the SenderDB
    auto start_time = std::chrono::high_resolution_clock::now(); 
    sender_db->insert_or_assign(sender_items);
    // The first step is to obtain OPRF values for these items, so we need to
    // create an oprf::OPRFReceiver object and use it to create an OPRF request
    oprf::OPRFReceiver oprf_receiver = receiver::Receiver::CreateOPRFReceiver(receiver_items);
    Request request = receiver::Receiver::CreateOPRFRequest(oprf_receiver);
    
    // Send the OPRF request on our communication channel (note the need to std::move it)
    channel.send(std::move(request));

    // The Sender must receive the OPRF request (need to convert it to OPRFRequest type)
    Request received_request = channel.receive_operation(sender_db->get_seal_context());
    OPRFRequest received_oprf_request = to_oprf_request(std::move(received_request));

    // Process the OPRF request and send a response back to the Receiver
    sender::Sender::RunOPRF(received_oprf_request, sender_db->get_oprf_key(), channel);

    // The Receiver can now get the OPRF response from the communication channel.
    // We need to extract the OPRF hashes from the response.
    Response response = channel.receive_response();
    OPRFResponse oprf_response = to_oprf_response(response);
    auto receiver_oprf_items = receiver::Receiver::ExtractHashes(
        oprf_response,
        oprf_receiver
    );

    // With the OPRF hashed Receiver's items, we are ready to create a PSI query.
    // First though, we need to create our Receiver object (assume here the Receiver
    // knows the PSI parameters). We need to keep the IndexTranslationTable object that
    // Receiver::create_query returns.
    receiver::Receiver receiver(params);
    pair<Request, receiver::IndexTranslationTable> query_data
        = receiver.create_query(receiver_oprf_items.first);
    receiver::IndexTranslationTable itt = query_data.second;
    request = std::move(query_data.first);

    // Now we are ready to send the PSI query request on our communication channel
    channel.send(std::move(request));

    // The Sender will then receive the PSI query request
    received_request = channel.receive_operation(sender_db->get_seal_context());
    QueryRequest received_query_request = to_query_request(received_request);

    // We need to extract the PSI query first
    sender::Query query(std::move(received_query_request), sender_db);

    // Process the PSI query request and send the response back to the Receiver
    sender::Sender::RunQuery(query, channel);

    // The Receiver then receives a QueryResponse object on the channel
    response = channel.receive_response();
    QueryResponse query_response = to_query_response(response);

    // The actual result data is communicated separately; the query response only
    // contains the number of ResultPart objects we expect to receive.
    uint32_t result_part_count = query_response->package_count;

    // Now loop to receive all of the ResultParts 
    vector<ResultPart> result_parts;
    while ((result_part_count--) != 0U) {
        ResultPart result_part = channel.receive_result(receiver.get_seal_context());
        result_parts.push_back(std::move(result_part));
    }
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;
    // Finally process the result
    vector<receiver::MatchRecord> results
        = receiver.process_result(receiver_oprf_items.second, itt, result_parts);
    std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
    
    // The results vector indicates match information; the order matches the order
    // of the original input vector receiver_items
    /*
    for (size_t i = 0; i < raw_receiver_items.size(); i++) {
        cout << "Item " << raw_receiver_items[i] << ": ";
        cout << (results[i].found ? "FOUND" : "NOT FOUND") << endl;
    }
    */
    /*
    yacl::parallel_for(0, nr, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * max_point_length;
      y_str[idx] =
          std::string(reinterpret_cast<const char*>(maskbuffer.data() + offset),
                      max_point_length);
    }
  });*/
    cout << "Communication bytes: " << channel.bytes_received() / (1024.0 * 1024.0) << " MB" << endl;
    return 0;
}
