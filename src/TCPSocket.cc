#include "sockets.hh"

TCPS::TCPSocket::TCPSocket(const std::string& addr, bool is_ipv6)
{
    try {
        set_addr(addr, is_ipv6);
    }
    catch (const std::exception& e)
    {
        throw e;
    }
    fd_ = socket((is_ipv6 ? AF_INET6 : AF_INET)
                 , SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (!::connect(fd_, addr_.get(), sizeof(*addr_)))
        throw TCPS::IOException("Connect failed");
}

bool TCPS::TCPSocket::set_addr(const std::string& addr, bool is_ipv6)
{
    auto column = addr.find(":");
    std::string body = addr.substr(0, column);
    std::string port = addr.substr(column + 1, addr.length() - column - 1);
    addr_ = std::shared_ptr<sockaddr>(new sockaddr);
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
    return true;
}

int TCPS::TCPSocket::send_msg(const std::string& message) const
{
    auto res = ::send(fd_, message.c_str(), message.size(), MSG_CONFIRM);
    if (res == 0)
        throw TCPS::IOException("message sending failed");
    return res;
}

std::string TCPS::TCPSocket::recieve() const
{
    std::string ret;
    char token[4096] = {0};
    int res = 0, count = 0;
    do {
        res = recv(fd_, token + count, 4096 - count, 0);
        if (res != -1)
            count += res;
        if (count == 4096)
        {
            ret += std::string(token);
            count = 0;
        }
    } while (res != 0 or errno == EAGAIN);
    token[count] = '\0';
    ret += std::string(token);
    return ret;
}
