#pragma once

#include <memory>
#include <exception>
#include <vector>
#include <iostream>
#include <sstream>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/signal.h>
#include <sys/epoll.h>

namespace TCPS
{
    class AbsTCPSocket
    {
        protected:
            int fd_;
            std::string last_error_;
        public:
            AbsTCPSocket(): fd_(-1), last_error_(""){};
            AbsTCPSocket(const AbsTCPSocket& other) = default;
            virtual bool set_addr(const std::string& addr, bool is_ipv6 = 0) = 0;
            virtual int send_msg(const std::string& message) const = 0;
            virtual std::string recieve() const = 0;
    };

    class TCPSocket : public AbsTCPSocket
    {
        protected:
            std::shared_ptr<sockaddr> addr_;
            bool connected_;
        public:
            TCPSocket();
            TCPSocket(const std::string& addr, bool is_ipv6 = 0);
            TCPSocket(const TCPSocket& other) = default;
            std::shared_ptr<sockaddr> get_addr() const { return addr_; }
            int get_fd() const { return fd_; }
            virtual bool set_addr(const std::string& addr, bool is_ipv6 = 0) override;
            virtual int send_msg(const std::string& message) const override;
            virtual std::string recieve() const override;
    };

    class TCPServ : public AbsTCPSocket
    {
        private:
            int epoll_;
            std::shared_ptr<epoll_event> event_;
            std::vector<int> accepted_sockets;
            bool binded_;
        public:
            static const int MAXEVENTS = 10;
            TCPServ() = default;
            TCPServ(const std::string& addr, bool is_ipv6 = 0);
            TCPServ(const TCPServ& s) = default;
            virtual bool set_addr(const std::string& addr, bool is_ipv6 = 0) override;
            void add_socket(const TCPSocket& socket);
            void add_socket(int fd);
            virtual int send_msg(const std::string& message) const override;
            int send_to(const std::string& message, const TCPS::TCPSocket& sock) const;
            virtual std::string recieve() const override;
    };

    class IOException : public std::runtime_error
    {
        private:
            int errno_;
            const char* what_arg;
        public:
            IOException(std::string str)
                : std::runtime_error(str)
                , errno_(errno)
                , what_arg(str.c_str())
            {}
            virtual const char *what() const noexcept override
            {
                std::string res(__FILE__);
                res += __LINE__;
                res += what_arg;
                res += " errno: ";
                res += errno_;
                return res.c_str();
            }
    };
}
