#include <iostream>
#include <filesystem>
#include <string>
#include <fstream>
#include <time.h>
#include <thread>
#include <mutex>
#include <queue>

#define ASIO_STANDALONE
#include <asio.hpp>

#include <imgui.h>
#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>

#include <GL/gl.h>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <crtdbg.h>

using asio::ip::tcp;

struct OPTIONS {
    int width = 900;
    int height = 600;

    std::string username;
    std::string current_recipient = "mainwindow";

    std::atomic_bool is_logged = false;
    std::atomic_bool is_retrieved = false;
    std::atomic_bool is_retrieved_requested = false;

    std::mutex mutex;

    std::vector<std::string> connections;
    std::unordered_map<std::string, std::vector<std::vector<std::string>>> history;

    std::queue<std::string> requests;

    const std::string delimeter = "<eos>";

    ImGuiWindowFlags main_window_flags =
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoTitleBar;

    ImGuiWindowFlags child_window_flags =
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse;

    RSA* public_key = nullptr;
    RSA* private_key = nullptr;
} options;

class Client
{
public:
    Client(asio::io_context& io_context);

    void connect(tcp::resolver::results_type& endpoints);
    void close();
    void push_request(const std::string& request);

private:
    void get_response();
    void send_request();

    asio::io_context& context;
    tcp::socket socket;
    std::queue<std::string> requests;
    std::string delimeter = "<eos>";
    std::mutex request_mutex;

    std::thread io_thread;
};

// application functions
const std::string current_date_time();
void save_credentials(std::string credentials);

std::string encrypt(std::shared_ptr<std::string> str);
std::string decrypt(std::shared_ptr<std::string> str);

void handle_login(std::shared_ptr<std::string> response_str);
void handle_response(std::shared_ptr<std::string> response_str);

// ImGUI functions
static void key_callback(GLFWwindow* window, int key, int scancode, int action, int mods);

// GUI functions
void login_register_window(Client& client);
void main_window(Client& client);

int main()
{
    //HWND hWnd = GetConsoleWindow();
    //ShowWindow(hWnd, SW_HIDE);

    std::string IP = "IP";
    std::string PORT = "PORT";
    
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    std::thread gui_thread;

    try
    {
        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::resolver::results_type endpoints = resolver.resolve(IP, PORT);

        Client client(io_context);
        
        gui_thread = std::thread(
            [&client] {
                if (!std::filesystem::exists("public.pem"))
                {
                    std::string request = "key";
                    client.push_request(request);
                }

                while (true)
                {
                    if (std::filesystem::exists("public.pem"))
                        break;

                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                login_register_window(client);

                if (options.is_logged && options.is_retrieved)
                {
                    main_window(client);
                }

                client.close();
            });

        client.connect(endpoints);
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << '\n';
    }
    
    gui_thread.join();

    _CrtDumpMemoryLeaks();

    return 0;
}

Client::Client(asio::io_context& io_context)
    : context(io_context), socket(io_context)
{ }

void Client::connect(tcp::resolver::results_type& endpoints)
{
    asio::connect(socket, endpoints);
    get_response();

    //io_thread = std::thread([this]() { context.run(); });
    context.run();
}

void Client::close()
{
    std::cout << "Application should close.";
    //io_thread.join();
    asio::post(context, [this]() { socket.close(); });
    context.stop();
}

void Client::push_request(const std::string& request)
{
    asio::post(context,
        [this, request]() {
            std::lock_guard<std::mutex> lock(request_mutex);

            bool write_in_progress = !requests.empty();
            requests.push(request);

            if (!write_in_progress)
            {
                send_request();
            }
        });
}

void Client::send_request()
{
    if (socket.is_open())
    {
        std::error_code ec;

        std::string request_size = std::to_string(requests.front().size()) + delimeter;
        asio::write(socket, asio::buffer(request_size.data(), request_size.size()), ec);

        if (!ec)
        {
            asio::write(socket, asio::buffer(requests.front().data(), requests.front().size()), ec);

            if (!ec)
            {
                requests.pop();

                if (!requests.empty())
                    send_request();
            }
            else
            {
                std::cerr << "Error sending request: " << ec.message() << '\n';
            }
        }
        else
        {
            std::cerr << "Error sending request size: " << ec.message() << '\n';
        }
    }
    else
    {
        std::cerr << "Socket is not open.\n";
    }
}

void Client::get_response()
{
    if (socket.is_open())
    {
        std::shared_ptr<asio::streambuf> buffer = std::make_shared<asio::streambuf>();
        buffer->consume(buffer->size());

        asio::async_read_until(socket, *buffer, delimeter,
            [this, buffer](const std::error_code& ec, std::size_t bytes) {
                if (!ec) {
                    std::istream input_stream(buffer.get());
                    std::string response_size_str;
                    std::getline(input_stream, response_size_str);

                    size_t delimiter_pos = response_size_str.find(delimeter);
                    if (delimiter_pos != std::string::npos) {
                        response_size_str = response_size_str.substr(0, delimiter_pos);
                        int response_size = std::stoi(response_size_str);

                        std::cout << "Response size received: " << response_size << '\n';

                        std::shared_ptr<std::string> response = std::make_shared<std::string>();

                        response->clear();
                        response->resize(response_size);

                        asio::async_read(socket, asio::buffer(response->data(), response_size),
                            [this, response](const std::error_code& ec, std::size_t bytes) {
                                if (!ec)
                                {
                                    if (options.is_logged)
                                    {
                                        std::cout << "Bytes received: " << bytes << '\n';
                                        handle_response(response);
                                    }
                                    else
                                    {
                                        std::cout << "Unencrypted response received: " << *response << '\n';
                                        handle_login(response);
                                    }
                                }
                                else
                                {
                                    std::cerr << "Error getting response: " << ec.message() << '\n';
                                }
                            });
                    }
                    else {
                        std::cerr << "Error: Delimiter not found in response size.\n";
                    }
                }
                else {
                    std::cerr << "Error getting response size: " << ec.message() << '\n';
                }

                get_response();
            });
    }
    else
    {
        std::cerr << "Socket is not open.\n";
    }
}

void handle_login(std::shared_ptr<std::string> response_str)
{
    if (*response_str == "wa.")
    {
        std::lock_guard<std::mutex> lock(options.mutex);

        options.is_logged = true;
    }
    else if (*response_str == "Connection closed by the server")
    {
        std::cout << "Connection closed by the server.\n";
    }
    else if (*response_str == "nawsua/op.") // No account with such username and/or password.
    {
        std::cout << "No account with such username and/or password.\n";
    }
    else if (*response_str == "le.") // Login error.
    {
        std::cout << "Login error.\n";
    }
    else if (*response_str == "Connection closed by the server")
    {
        std::cout << "Connection closed by the server\n";
    }
    else if (*response_str == "e:awteaae.tli.") // Error: account with this email address already exists. Try logging in.
    {
        std::cout << "Error: account with this email address already exists. Try logging in.\n";
    }
    else if (*response_str == "e:awtuae.tdu.") // Error: account with this username already exists. Try different username.
    {
        std::cout << "Error: account with this username already exists. Try different username.\n";
    }
    else if (*response_str == "re.") // Registration error.
    {
        std::cout << "Registration error.\n";
    }
    else
    {
        std::stringstream line(*response_str);
        std::string token;

        std::getline(line, token, '-');

        if (token == "key")
        {
            std::getline(line, token, '\0');

            std::string public_key_server = "";
            std::stringstream line(token);

            while (std::getline(line, token, '|'))
            {
                public_key_server += token;

                if (token == "-----END RSA PUBLIC KEY-----")
                    break;

                public_key_server += "\n";
            }

            std::ofstream public_key_file("public.pem");
            public_key_file << public_key_server;
            public_key_file.close();
        }
    }
}

void handle_response(std::shared_ptr<std::string> response_str)
{
    std::cout << "Encrypted response received: ";

    std::string decrypted_response = decrypt(response_str);

    std::cout << decrypted_response << '\n';

    if (decrypted_response == "retrieve_connections-<eof>")
    {
        options.is_retrieved = true;
    }
    else if (decrypted_response == "se.")
    {
        std::cout << "Sync error.\n";
    }
    else if (decrypted_response == "ce.")
    {
        std::cout << "Connection error.\n";
    }
    else if (decrypted_response == "nuwsu.")
    {
        std::cout << "No user with such username.\n";
    }
    else if (decrypted_response == "re.")
    {
        std::cout << "Retrieve error.\n";
    }
    else
    {
        std::string token;
        std::stringstream line(decrypted_response);

        std::getline(line, token, '-');

        if (token == "sync")
        {
            std::string recipient_username;
            std::vector<std::string> tokens;

            std::getline(line, recipient_username, '|');

            std::getline(line, token, '|'); // destination
            tokens.push_back(token);

            std::getline(line, token, '|'); // date_time
            tokens.push_back(token);

            std::getline(line, token, '\0'); // message
            tokens.push_back(token);

            options.history[recipient_username].push_back(tokens);
        }
        else if (token == "connect")
        {
            std::getline(line, token, '\0');
            options.connections.push_back(token);
        }
        else if (token == "retrieve_history")
        {
            std::vector<std::vector<std::string>> temp_history;
            std::vector<std::string> tokens;
            std::string token;
            std::string recipient_username;

            std::getline(line, recipient_username, '|'); // recipient_username

            std::getline(line, token, '|'); // destination
            tokens.push_back(token);

            std::getline(line, token, '|'); // date_time
            tokens.push_back(token);

            std::getline(line, token, '\0'); // message
            tokens.push_back(token);

            if (options.history.find(recipient_username) == options.history.end())
                options.history[recipient_username] = temp_history;

            options.history[recipient_username].push_back(tokens);
        }
        else if (token == "retrieve_connections")
        {
            std::getline(line, token, '\0');
            options.connections.push_back(token);
        }
    }
}

void main_window(Client& client)
{
    char connection_username[20] = "";
    char buff_message[1024] = "";

    bool is_connect = false;

    auto LoadTextureFromFile = [](const char* filename, GLuint* out_texture, int* out_width, int* out_height)
        {
            // Load from file
            int image_width = 0;
            int image_height = 0;
            unsigned char* image_data = stbi_load(filename, &image_width, &image_height, NULL, 4);

            if (image_data == NULL)
                return false;

            // Create a OpenGL texture identifier
            GLuint image_texture;
            glGenTextures(1, &image_texture);
            glBindTexture(GL_TEXTURE_2D, image_texture);

            // Setup filtering parameters for display
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

            // Upload pixels into texture
#if defined(GL_UNPACK_ROW_LENGTH) && !defined(__EMSCRIPTEN__)
            glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
#endif
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image_width, image_height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
            stbi_image_free(image_data);

            *out_texture = image_texture;
            *out_width = image_width;
            *out_height = image_height;

            return true;
        };

    assert(glfwInit() && "Could not initialize GLFW!");

    GLFWwindow* window = glfwCreateWindow(options.width, options.height, "Giga Chat", nullptr, nullptr);

    glfwSetErrorCallback([](int error, const char* description)
        { fprintf(stderr, "Error: %s\n", description); }
    );

    glfwSetKeyCallback(window, key_callback);
    glfwMakeContextCurrent(window);

    IMGUI_CHECKVERSION();

    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags = ImGuiViewportFlags_IsPlatformMonitor;

    ImGui::StyleColorsDark();
    ImGui::GetStyle().FramePadding.y = 12.0f;
    ImGui::GetStyle().WindowBorderSize = 1.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 120");

    // variables
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    GLFWimage images[1];
    images[0].pixels = stbi_load("giga.png", &images[0].width, &images[0].height, 0, 4);

    if (images[0].pixels)
        glfwSetWindowIcon(window, 1, images);

    int my_image_width = 0;
    int my_image_height = 0;
    GLuint my_image_texture = 0;
    bool ret = LoadTextureFromFile("giga.png", &my_image_texture, &my_image_width, &my_image_height);
    IM_ASSERT(ret);

    while (!glfwWindowShouldClose(window))
    {
        auto start = std::chrono::high_resolution_clock::now();
        glClearColor(0.1, 0.1, 0.1, 1.0);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2{ (float)options.width, (float)options.height });
        ImGui::Begin("mainwindow", 0, options.main_window_flags);

        // top menu bar
        {
            ImGui::SameLine();
            ImGui::SetCursorPosX(0);
            if (ImGui::BeginMainMenuBar())
            {
                if (ImGui::BeginMenu("file"))
                {
                    if (ImGui::MenuItem("export chat"))
                    {

                    }

                    if (ImGui::MenuItem("delete credentials"))
                    {

                    }

                    if (ImGui::MenuItem("log out"))
                    {

                    }

                    if (ImGui::MenuItem("exit"))
                    {

                    }
                    ImGui::EndMenu();
                }

                if (ImGui::BeginMenu("connect"))
                {
                    is_connect = !is_connect;
                    ImGui::EndMenu();
                }

                //ImGui::Text("%f", io.Framerate);

                ImGui::EndMainMenuBar();

                if (is_connect)
                {
                    ImGui::SetNextWindowPos(ImVec2((float)(options.width - 400) / 2, (float)(options.height - 400) / 2));
                    ImGui::SetNextWindowSize(ImVec2{ 400.0f, 400.0f });
                    if (ImGui::Begin("##connect", &is_connect, options.child_window_flags))
                    {
                        ImGui::SameLine();
                        ImGui::SetCursorPosX(0);
                        if (ImGui::BeginChild("connect", ImVec2(0, 0), true, options.child_window_flags))
                        {
                            ImGui::Text("username: ");

                            ImGui::SameLine();
                            ImGui::InputText("##username", connection_username, 20, 0);

                            if (ImGui::Button("connect"))
                            {
                                if (std::strlen(connection_username) == 0)
                                {
                                    std::cout << "username should not be empty.\n";
                                }
                                else if (!options.connections.empty() &&
                                    std::find(options.connections.begin(),
                                        options.connections.end(),
                                        (std::string)connection_username) != options.connections.end())
                                {
                                    std::cout << "you are already connected with this username.\n";
                                }
                                else if ((std::string)connection_username == options.username)
                                {
                                    std::cout << "this is your username.\n";
                                }
                                else
                                {

                                    std::string request = "connect " + options.username + " " + (std::string)connection_username;
                                    
                                    std::shared_ptr<std::string> request_ptr = std::make_shared<std::string>(request);
                                    std::string encrypted_request = encrypt(request_ptr);

                                    client.push_request(encrypted_request);

                                    std::strcpy(connection_username, "");
                                }
                            }

                            ImGui::EndChild();
                        }

                        ImGui::End();
                    }
                }
            }
        }

        // left chats window 
        {
            ImGui::NewLine();
            ImGui::SetCursorPos(ImVec2(5, 35));
            if (ImGui::BeginChild("chats", ImVec2(0, 0), true, options.main_window_flags))
            {
                for (auto it = options.connections.begin(); it < options.connections.end(); ++it)
                {
                    ImGui::Selectable((*it).c_str(), false, 0, ImVec2(285, 20));

                    if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
                    {
                        options.current_recipient = (*it);
                    }
                }

                ImGui::EndChild();
            }
        }

        // right chat window
        {
            ImGui::SameLine();
            ImGui::SetCursorPos(ImVec2(300, 35));
            if (options.current_recipient == "mainwindow")
            {
                if (ImGui::BeginChild("main window", ImVec2(0, 0), true, options.main_window_flags))
                {
                    ImGui::Image(
                        (void*)(intptr_t)my_image_texture,
                        ImVec2{ (float)options.width - 330,
                        (float)options.height - 65 }
                    );

                    ImGui::EndChild();
                }
            }
            else
            {
                if (ImGui::BeginChild("current chat", ImVec2(0, 0), true, options.main_window_flags))
                {
                    for (auto it = options.history[options.current_recipient].begin(); it < options.history[options.current_recipient].end(); ++it)
                    {
                        if ((*it)[0] == "out")
                        {
                            auto posx = std::max<float>((ImGui::GetCursorPosX()
                                + ImGui::GetColumnWidth()
                                - ImGui::CalcTextSize(("(" + (*it)[1] + "): " + (*it)[2]).c_str()).x
                                - ImGui::GetScrollX()
                                - 2 * ImGui::GetStyle().ItemSpacing.x), (options.width - 300) / 2);

                            if (posx > ImGui::GetCursorPosX())
                                ImGui::SetCursorPosX(posx);
                        }
                        ImGui::TextWrapped(((*it)[2] + "\n" + (*it)[1]).c_str());
                    }

                    ImGui::SetCursorPos(ImVec2(20, options.height - 100));
                    ImGui::SetNextItemWidth((float)options.width - 450);
                    ImGui::InputText("##message", buff_message, 1024);

                    ImGui::SameLine();
                    ImGui::SetCursorPosX((float)options.width - 370);
                    if (ImGui::Button("send", ImVec2(50, 0)) && std::strlen(buff_message) != 0)
                    {
                        std::string request = "sync " + options.username + " " +
                            options.current_recipient + "|out|" +
                            current_date_time() + "|" + (std::string)buff_message;
                        
                        std::shared_ptr<std::string> request_ptr = std::make_shared<std::string>(request);
                        std::string encrypted_request = encrypt(request_ptr);

                        client.push_request(encrypted_request);

                        std::strcpy(buff_message, "");
                    }

                    ImGui::EndChild();
                }
            }
        }

        glfwGetWindowSize(window, &options.width, &options.height);

        ImGui::End();
        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwPollEvents();
        glfwSwapBuffers(window);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    glfwTerminate();
}

void login_register_window(Client& client)
{
    bool register_option = true;
    std::string public_key;

    int width = 480;
    int height = 480;

    char buffer_username[20] = "";
    char buffer_email[40] = "";
    char buffer_password[20] = "";

    std::string saved_username;
    std::string saved_password;

    auto generate_keys = []()
        {
            int bits = 2048;
            unsigned long e = RSA_F4;

            RSA* rsa = RSA_new();

            BIGNUM* bne = BN_new();
            BN_set_word(bne, e);
            RSA_generate_key_ex(rsa, bits, bne, NULL);

            BIO* bio = BIO_new(BIO_s_mem());

            PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

            char* privKeyData;
            size_t privKeyLen = BIO_get_mem_data(bio, &privKeyData);
            std::string privateKey(privKeyData, privKeyLen);

            FILE* privKeyFile = fopen("private.pem", "wb");
            fwrite(privateKey.c_str(), 1, privateKey.length(), privKeyFile);
            fclose(privKeyFile);

            RSA* publicKey = RSAPublicKey_dup(rsa);
            char* pubKeyPEM = NULL;
            BIO* pubBio = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(pubBio, publicKey);
            BIO_get_mem_data(pubBio, &pubKeyPEM);

            std::string publicKeyString(pubKeyPEM);

            std::string token;
            std::stringstream line(publicKeyString);

            publicKeyString = "";
            while (std::getline(line, token, '\n'))
            {
                publicKeyString += token;

                if (token == "-----END RSA PUBLIC KEY-----")
                    break;

                publicKeyString += "|";
            }

            RSA_free(rsa);
            BN_free(bne);
            BIO_free_all(bio);
            RSA_free(publicKey);
            BIO_free(pubBio);

            return publicKeyString;
        };

    auto checkSpaces = [](char str[20])
        {
            for (int i = 0; i < 20; i++)
            {
                if (str[i] == '\0')
                    break;

                if (str[i] == ' ')
                    return false;
            }

            return true;
        };

    if (!std::filesystem::exists("private.pem"))
    {
        register_option = true;
        public_key = generate_keys();
    }

    if (std::filesystem::exists("public.pem") && std::filesystem::exists("private.pem"))
    {
        BIO* bio_public = BIO_new_file("public.pem", "rb");
        if (!bio_public)
        {
            std::cerr << "Error opening file.\n";
        }
        else
        {
            options.public_key = PEM_read_bio_RSAPublicKey(bio_public, nullptr, nullptr, nullptr);
        }

        BIO_free(bio_public);

        BIO* bio_private = BIO_new_file("private.pem", "rb");
        if (!bio_private)
        {
            std::cerr << "Error opening file.\n";
        }
        else
        {
            options.private_key = PEM_read_bio_RSAPrivateKey(bio_private, nullptr, nullptr, nullptr);
        }

        BIO_free(bio_private);
    }

    if (std::filesystem::exists("credentials.txt") && options.private_key && options.public_key)
    {
        register_option = false;

        std::string saved_credentials;
        std::ifstream ifile("credentials.txt");
        std::getline(ifile, saved_credentials);

        ifile.close();

        std::string saved_username = saved_credentials.substr(0, saved_credentials.find(' '));
        std::string saved_password = saved_credentials.substr(saved_credentials.find(' ') + 1, saved_credentials.size());

        std::strcpy(buffer_username, saved_username.c_str());
        std::strcpy(buffer_password, saved_password.c_str());
    }

    assert(glfwInit() && "Could not initialize GLFW!");

    GLFWwindow* initial_window = glfwCreateWindow((float)width, (float)height, "Giga Chat", nullptr, nullptr);

    glfwSetErrorCallback([](int error, const char* description)
        { fprintf(stderr, "Error: %s\n", description); }
    );

    glfwSetKeyCallback(initial_window, key_callback);
    glfwMakeContextCurrent(initial_window);

    IMGUI_CHECKVERSION();

    ImGui::CreateContext();

    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags = ImGuiViewportFlags_IsPlatformMonitor;

    ImGui::StyleColorsDark();
    ImGui::GetStyle().FramePadding.y = 12.0f;
    ImGui::GetStyle().WindowBorderSize = 0.0f;

    ImGui_ImplGlfw_InitForOpenGL(initial_window, true);
    ImGui_ImplOpenGL3_Init("#version 120");

    // variables
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    GLFWimage images[1];
    images[0].pixels = stbi_load("giga.png", &images[0].width, &images[0].height, 0, 4);

    if (images[0].pixels)
        glfwSetWindowIcon(initial_window, 1, images);

    bool requirements_met;

    while (!glfwWindowShouldClose(initial_window))
    {
        glClearColor(1.0, 1.0, 1.0, 1.0);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // main window
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2{ (float)width, (float)height });
        ImGui::Begin("LoginWindow", 0, options.main_window_flags);

        {
            ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Welcome to Giga Chat!").x) / 2.f);
            ImGui::SetCursorPosY(10.0f);
            ImGui::Text("Welcome to Giga Chat!");

            ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize("Please, register or log in.").x) / 2.f);
            ImGui::Text("Please, register or log in.");

            ImGui::NewLine();
            if (!register_option && ImGui::BeginChild("Login", ImVec2(0, 0), true, options.main_window_flags))
            {
                ImGui::Text("Username: ");

                ImGui::SameLine();
                ImGui::InputText("##username", buffer_username, 20, 0);

                ImGui::Text("Password: ");
                ImGui::SameLine();
                ImGui::InputText("##password", buffer_password, 20, ImGuiInputTextFlags_Password);

                (checkSpaces(buffer_username) && checkSpaces(buffer_password)) ?
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0, 1.0, 0.0, 1.0)) :
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0, 0.0, 0.0, 1.0));
                ImGui::Text("There should be no empty spaces.");
                ImGui::PopStyleColor();

                requirements_met = checkSpaces(buffer_username) &&
                    checkSpaces(buffer_password) &&
                    (std::strlen(buffer_username) >= 2) &&
                    (std::strlen(buffer_password) >= 6);

                ImGui::NewLine();
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcItemWidth()) / 2.f);
                ImGui::BeginDisabled(!requirements_met);
                if (ImGui::Button("Login"))
                {
                    std::string request = "login " +
                        std::string(buffer_username) + " " +
                        std::string(buffer_password);

                    std::shared_ptr<std::string> request_ptr = std::make_shared<std::string>(request);
                    std::string encrypted_request = encrypt(request_ptr);

                    client.push_request(encrypted_request);
                }
                ImGui::EndDisabled();

                ImGui::NewLine();
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcItemWidth()) / 2.f);
                if (ImGui::Button("Register instead"))
                {
                    std::strcpy(buffer_username, "");
                    std::strcpy(buffer_email, "");
                    std::strcpy(buffer_password, "");

                    register_option = !register_option;
                }

                ImGui::EndChild();
            }
            else if (register_option && ImGui::BeginChild("Register", ImVec2(0, 0), true, options.main_window_flags))
            {
                ImGui::Text("Username:       ");

                ImGui::SameLine();
                ImGui::InputText("##username", buffer_username, 20, 0);

                ImGui::Text("E-mail address: ");

                ImGui::SameLine();
                ImGui::InputText("##email", buffer_email, 40, 0);

                ImGui::Text("Password:       ");
                ImGui::SameLine();
                ImGui::InputText("##password", buffer_password, 20, ImGuiInputTextFlags_Password);

                ImGui::Text("The username should be unique.");

                (checkSpaces(buffer_username) && checkSpaces(buffer_email) && checkSpaces(buffer_password)) ?
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0, 1.0, 0.0, 1.0)) :
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0, 0.0, 0.0, 1.0));
                ImGui::Text("There should be no empty spaces.");
                ImGui::PopStyleColor();

                (std::strlen(buffer_password) >= 6) ?
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0, 1.0, 0.0, 1.0)) :
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0, 0.0, 0.0, 1.0));
                ImGui::Text("The password should contain at least 6 characters.");

                ImGui::PopStyleColor();

                requirements_met = (std::strlen(buffer_password) >= 6) &&
                    (std::strlen(buffer_email) >= 6) &&
                    (std::strlen(buffer_username) >= 2) &&
                    checkSpaces(buffer_username) &&
                    checkSpaces(buffer_email) &&
                    checkSpaces(buffer_password);

                ImGui::NewLine();
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcItemWidth()) / 2.f);
                ImGui::BeginDisabled(!requirements_met);
                if (ImGui::Button("Register"))
                {
                    std::string request = "register " +
                        std::string(buffer_username) + " " +
                        std::string(buffer_email) + " " +
                        std::string(buffer_password) + " " +
                        public_key;

                    std::shared_ptr<std::string> request_ptr = std::make_shared<std::string>(request);
                    std::string encrypted_request = encrypt(request_ptr);

                    client.push_request(encrypted_request);
                }
                ImGui::EndDisabled();

                ImGui::NewLine();
                ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcItemWidth()) / 2.f);
                if (ImGui::Button("Login instead"))
                {
                    register_option = !register_option;
                }

                ImGui::EndChild();
            }
        }

        glfwGetWindowSize(initial_window, &width, &height);

        ImGui::End();
        ImGui::Render();
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwPollEvents();
        glfwSwapBuffers(initial_window);

        if (options.is_logged && !options.is_retrieved_requested)
        {
            options.is_retrieved_requested = true;

            options.username = std::string(buffer_username);

            save_credentials(std::string(buffer_username) + " " + std::string(buffer_password));

            std::string request = "retrieve " + options.username;

            std::shared_ptr<std::string> request_ptr = std::make_shared<std::string>(request);
            std::string encrypted_request = encrypt(request_ptr);

            client.push_request(encrypted_request);
        }
        else if (options.is_logged && options.is_retrieved)
        {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    glfwTerminate();

    stbi_image_free(images[0].pixels);
}

void save_credentials(std::string credentials)
{
    std::stringstream line(credentials);
    std::getline(line, options.username, ' ');

    if (!std::filesystem::exists("credentials.txt"))
    {
        std::ofstream ofile("credentials.txt");
        ofile << credentials;
        ofile.close();
    }
    else
    {
        std::string saved_credentials;
        std::ifstream ifile("credentials.txt");
        std::getline(ifile, saved_credentials);
        ifile.close();

        if (saved_credentials != credentials)
        {
            std::ofstream ofile("credentials.txt");
            ofile << credentials;
            ofile.close();
        }
    }
}

std::string encrypt(std::shared_ptr<std::string> str)
{
    const int chunk_size = 240;
    const int rsa_len = RSA_size(options.public_key);

    std::string encrypted_string;

    for (int i = 0; i < str->length(); i += chunk_size)
    {
        int remaining = std::min(chunk_size, static_cast<int>(str->length() - i));
        std::vector<unsigned char> encrypted_text(rsa_len);

        int encrypt_size = RSA_public_encrypt(remaining,
            reinterpret_cast<const unsigned char*>(str->substr(i, remaining).c_str()),
            encrypted_text.data(), options.public_key, RSA_PKCS1_PADDING);

        if (encrypt_size == -1) {
            std::cerr << "Encryption failed: " << ERR_error_string(ERR_get_error(), NULL) << '\n';
            encrypted_string = "";

            break;
        }
        else
        {
            encrypted_string += std::string(reinterpret_cast<char*>(encrypted_text.data()), encrypt_size);
        }
    }

    return encrypted_string;
}

std::string decrypt(std::shared_ptr<std::string> str)
{
    const int chunk_size = 256;
    const int rsa_len = RSA_size(options.private_key);

    std::string decrypted_string;

    for (int i = 0; i < str->length(); i += chunk_size)
    {
        int remaining = std::min(chunk_size, static_cast<int>(str->length() - i));
        std::vector<unsigned char> decrypted_text(rsa_len);

        int decrypt_size = RSA_private_decrypt(remaining,
            reinterpret_cast<const unsigned char*>(str->substr(i, remaining).c_str()),
            decrypted_text.data(), options.private_key, RSA_PKCS1_PADDING);

        if (decrypt_size == -1)
        {
            std::cerr << "Decryption failed: " << ERR_error_string(ERR_get_error(), NULL) << '\n';
            decrypted_string = "";

            break;
        }
        else
        {
            decrypted_string += std::string(reinterpret_cast<char*>(decrypted_text.data()), decrypt_size);
        }
    }

    return decrypted_string;
}

const std::string current_date_time()
{
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);

    strftime(buf, sizeof(buf), "%m/%d/%Y-%X", &tstruct);

    return buf;
}

static void key_callback(GLFWwindow* window, int key, int scancode, int action, int mods) {
    if (key == GLFW_KEY_ESCAPE && action == GLFW_PRESS)
        glfwSetWindowShouldClose(window, GLFW_TRUE);
}
