#include "sockets.hh"

TCPS::TCPServ::TCPServ(const std::string& addr, bool is_ipv6)
{
    fd_ = socket((is_ipv6 ? AF_INET6 : AF_INET)
                 , SOCK_STREAM | SOCK_NONBLOCK, 0);
    binded_ = set_addr(addr, is_ipv6);
    epoll_ = ::epoll_create(0);
    event_ = std::make_shared<epoll_event>();
}

bool TCPS::TCPServ::set_addr(const std::string& addr, bool is_ipv6)
{
    auto column = addr.find(":");
    std::string body = addr.substr(0, column);
    std::string port = addr.substr(column + 1, addr.length() - column - 1);
    auto addr_ = std::shared_ptr<sockaddr>(new sockaddr);
    if (is_ipv6)
    {
        auto struct_addr = new in6_addr;
        if (!inet_pton(AF_INET6, body.c_str(), struct_addr))
        {
            throw std::invalid_argument("Cannot init a socket to invalid address");
        }
        auto sin = ((sockaddr_in6*)(addr_.get()));
        sin->sin6_family = AF_INET6;
        sin->sin6_port = stoi(port);
        sin->sin6_addr = *struct_addr;
        //delete struct_addr;
    }
    else
    {
        auto struct_addr = new in_addr;
        if (!inet_pton(AF_INET, body.c_str(), struct_addr))
        {
            throw std::invalid_argument("Cannot init a socket to invalid address");
        }
        auto sin = ((sockaddr_in*)(addr_.get()));
        sin->sin_family = AF_INET;
        sin->sin_port = stoi(port);
        sin->sin_addr = *struct_addr;
        //delete struct_addr;
    }
    return ::bind(fd_, addr_.get(), sizeof(*(addr_.get())));
}

int TCPS::TCPServ::send_to(const std::string& message,
                           const TCPS::TCPSocket& sock) const
{
    return ::sendto(fd_, message.c_str(), message.size(), 0,
           sock.get_addr().get(), sizeof(sock.get_addr().get()));
}

int TCPS::TCPServ::send_msg(const std::string& message) const
{
    std::cout << message << std::endl;
    return 1;
}

void TCPS::TCPServ::add_socket(const TCPSocket& socket)
{
    epoll_event event;
    event.data.fd = socket.get_fd();
    event.events = EPOLLIN | EPOLLET;
    epoll_ctl(epoll_, EPOLL_CTL_ADD, fd_, &event);
}

std::string TCPS::TCPServ::recieve() const
{
    epoll_event* events = (epoll_event*)calloc(sizeof(epoll_event), MAXEVENTS);
    int nfd = epoll_wait(epoll_, events, TCPS::TCPServ::MAXEVENTS, 0);
    sockaddr inaddr;
    socklen_t len = sizeof(sockaddr);
    for (int i = 0; i < nfd; ++i)
    {
        while (true)
        {
            int insock = -1;
            if (events->data.fd == fd_ and accepted_sockets.size() != MAXEVENTS)
                insock = accept(events->data.fd, &inaddr, &len);
            if (insock == -1 and (errno != EAGAIN || errno != EWOULDBLOCK))
            {
                perror("app");
                break;
            }
            else if (insock == -1)
                break;
            else
            {
                char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
                int s = getnameinfo (&inaddr, len,
                        hbuf, sizeof hbuf,
                        sbuf, sizeof sbuf,
                        NI_NUMERICHOST | NI_NUMERICSERV);

                if (s == 0)
                {
                    std::cout << "Accepted connexion on desciptor"
                              << insock << "(host=" << hbuf
                              << ", port=" << sbuf << ")\n";
                }
                events->data.fd = insock;
                events->data.fd = EPOLLIN | EPOLLET;
                s = epoll_ctl(epoll_, EPOLL_CTL_ADD, insock, events);
            }
        }
    }
    return "";
}
