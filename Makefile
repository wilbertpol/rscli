CXX = g++
CXXFLAGS = -g -O -Wall
LDFLAGS = -lz

OBJDIR = obj
SRCS = file.cpp psarc.cpp main.cpp

OBJS = $(SRCS:.cpp=.o)
DEPS = $(SRCS:.cpp=.d)

all: $(OBJDIR) rscli

rscli: $(addprefix $(OBJDIR)/, $(OBJS))
	$(CXX) -o $@ $^ $(LDFLAGS)

$(OBJDIR):
	mkdir $(OBJDIR)

$(OBJDIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -MMD -c $< -o $@

clean:
	rm -rf rscli $(OBJDIR)

-include $(addprefix $(OBJDIR)/, $(DEPS))
